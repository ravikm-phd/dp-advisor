"""Backend for the DP-Advice dashboard: a few JSON endpoints plus static files.

Sandbox queries run real diffprivlib mechanisms (Laplace, analytic Gaussian,
geometric, snapping) through the advice pipeline. Uploaded Python is only linted,
never executed.
"""

import json
import math
import os
import sys
import threading
import time
import uuid
import numpy as np
import diffprivlib.mechanisms as dp_mech
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, unquote

# lets `python web/app.py` find dp_advice without installing it
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dp_advice import (
    DPCall, run_dp_call, DPAdviceError, SanitizedExecutionError,
    GlobalPrivacyAccountant, NISTEnforcer, InMemoryAuditLogger,
)
from dp_advice.analyzer.static_linter import analyze_python_code

class NumpyJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.bool_, np.generic)):
            return obj.item()
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
INDEX_FILE = os.path.join(BASE_DIR, "templates", "index.html")
STATIC_DIR = os.path.realpath(os.path.join(BASE_DIR, "static"))
MAX_REQUEST_BYTES = 64 * 1024
MAX_CODE_CHARACTERS = 48 * 1024
SESSION_TTL_SECONDS = 60 * 60
MAX_SESSIONS = 500
MAX_QUERY_EPSILON = 10.0  # our per-query cap; NIST SP 800-226 doesn't set one


def _scale_of(mech):
    """Noise scale as the mechanism reports it. _scale is private in diffprivlib, so it may be missing."""
    scale = getattr(mech, "_scale", None)
    return float(scale) if isinstance(scale, (int, float)) else None


def _build_laplace(p):
    mech = dp_mech.Laplace(epsilon=p["epsilon"], sensitivity=p["sensitivity"], random_state=p["seed"])
    b = p["sensitivity"] / p["epsilon"]
    return mech, {
        "mechanism": "Laplace Mechanism",
        "formula_param": f"b = \\frac{{\\Delta f}}{{\\epsilon}} = \\frac{{{p['sensitivity']}}}{{{p['epsilon']}}} = {b:.4f}",
        "param_name": "Laplace Scale Parameter (b)",
        "param_value": b,
    }


def _build_gaussian(p):
    mech = dp_mech.GaussianAnalytic(
        epsilon=p["epsilon"], delta=p["delta"], sensitivity=p["sensitivity"], random_state=p["seed"]
    )
    sigma = _scale_of(mech)
    shown = f"{sigma:.4f}" if sigma is not None else "\\text{not exposed by the library}"
    return mech, {
        "mechanism": "Analytic Gaussian Mechanism",
        "formula_param": f"\\sigma \\text{{ solved numerically for }} \\epsilon={p['epsilon']},\\ \\delta={p['delta']:.1e},\\ \\Delta_2 f={p['sensitivity']}: \\quad \\sigma = {shown}",
        "param_name": "Gaussian Standard Deviation (σ)",
        "param_value": sigma,
    }


def _build_geometric(p):
    mech = dp_mech.Geometric(epsilon=p["epsilon"], sensitivity=int(p["sensitivity"]), random_state=p["seed"])
    alpha = math.exp(-p["epsilon"] / p["sensitivity"])
    return mech, {
        "mechanism": "Geometric Mechanism",
        "formula_param": f"\\alpha = e^{{-\\epsilon / \\Delta f}} = e^{{-{p['epsilon']} / {int(p['sensitivity'])}}} = {alpha:.6f}",
        "param_name": "Geometric Parameter (α)",
        "param_value": alpha,
    }


def _build_snapping(p):
    mech = dp_mech.Snapping(
        epsilon=p["epsilon"], sensitivity=p["sensitivity"], lower=p["lower"], upper=p["upper"],
        random_state=p["seed"],
    )
    eff = float(mech.effective_epsilon())
    return mech, {
        "mechanism": "Snapping Mechanism (Mironov 2012, diffprivlib implementation)",
        "formula_param": f"\\epsilon_{{\\text{{internal}}}} = {eff:.12f} \\le \\epsilon = {p['epsilon']}",
        "param_name": "Internal epsilon used for sampling",
        "param_value": eff,
    }


# mechanism id -> (advice key, builder, uses delta, integer-valued)
MECHANISMS = {
    "laplace": ("diffprivlib.mechanisms.Laplace.randomise", _build_laplace, False, False),
    "gaussian": ("diffprivlib.mechanisms.GaussianAnalytic.randomise", _build_gaussian, True, False),
    "geometric": ("diffprivlib.mechanisms.Geometric.randomise", _build_geometric, False, True),
    "snapping": ("diffprivlib.mechanisms.Snapping.randomise", _build_snapping, False, False),
}
_MECHANISM_BY_CLASS = {
    "diffprivlib.mechanisms.Laplace": "laplace",
    "diffprivlib.mechanisms.Gaussian": "gaussian",
    "diffprivlib.mechanisms.GaussianAnalytic": "gaussian",
    "diffprivlib.mechanisms.Geometric": "geometric",
    "diffprivlib.mechanisms.Snapping": "snapping",
}


def _optional_positive_int(value):
    """-> (ok, value or None)"""
    if value is None or value == "":
        return True, None
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return False, None
    return (number > 0, number if number > 0 else None)
ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.environ.get(
        "ALLOWED_ORIGINS",
        "https://privability.works,https://www.privability.works",
    ).split(",")
    if origin.strip()
}


class DemoSession:
    def __init__(self):
        self.accountant = GlobalPrivacyAccountant(total_epsilon=5.0, total_delta=1e-5)
        self.nist = NISTEnforcer(max_epsilon=MAX_QUERY_EPSILON)
        self.logger = InMemoryAuditLogger(max_entries=100)
        self.last_seen = time.monotonic()
        self.lock = threading.RLock()


_sessions = {}
_sessions_lock = threading.Lock()


def get_demo_session(session_id):
    now = time.monotonic()
    with _sessions_lock:
        expired = [
            key for key, session in _sessions.items()
            if now - session.last_seen > SESSION_TTL_SECONDS
        ]
        for key in expired:
            del _sessions[key]

        session = _sessions.get(session_id)
        if session is None:
            if len(_sessions) >= MAX_SESSIONS:
                oldest = min(_sessions, key=lambda key: _sessions[key].last_seen)
                del _sessions[oldest]
            session = DemoSession()
            _sessions[session_id] = session
        session.last_seen = now
        return session


def serialize_session_request(method):
    def wrapped(self):
        if not urlparse(self.path).path.startswith("/api/"):
            return method(self)
        try:
            session_id = str(uuid.UUID(self.headers.get("X-DP-Advice-Session", "")))
        except (ValueError, AttributeError):
            return method(self)

        session = get_demo_session(session_id)
        with session.lock:
            self._request_session = session
            try:
                return method(self)
            finally:
                del self._request_session
    return wrapped


class DPAdviceHTTPHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, X-DP-Advice-Session",
            )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _public_file(self, path):
        """The file a URL path may serve: the index page or a file inside static/. None otherwise."""
        clean_path = unquote(urlparse(path).path)
        if clean_path in ("/", "/index.html"):
            return INDEX_FILE
        if clean_path.startswith("/static/"):
            try:
                candidate = os.path.realpath(os.path.join(STATIC_DIR, clean_path[len("/static/"):]))
            except ValueError:
                return None
            # realpath collapses ../ and symlinks, so anything that escapes static/ fails this check
            if candidate.startswith(STATIC_DIR + os.sep) and os.path.isfile(candidate):
                return candidate
        return None

    def translate_path(self, path):
        return self._public_file(path) or os.path.join(STATIC_DIR, "does-not-exist")

    def send_head(self):
        # nothing outside the index page and static/ is ever served, and no directory listings
        if self._public_file(self.path) is None:
            self.send_error(404, "File not found")
            return None
        return super().send_head()

    def list_directory(self, path):
        self.send_error(404, "File not found")
        return None

    def _send_json(self, data, status=200):
        body = json.dumps(data, cls=NumpyJSONEncoder).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_session(self):
        if hasattr(self, "_request_session"):
            return self._request_session
        try:
            session_id = str(uuid.UUID(self.headers.get("X-DP-Advice-Session", "")))
        except (ValueError, AttributeError):
            self._send_json({"error": "A valid DP-Advice session ID is required"}, status=400)
            return None
        return get_demo_session(session_id)

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    @serialize_session_request
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/api/status":
            session = self._get_session()
            if session is None:
                return
            status_data = session.accountant.get_status()
            status_data["max_query_epsilon"] = session.nist.max_epsilon
            self._send_json(status_data)
            return
        elif parsed.path == "/api/logs":
            session = self._get_session()
            if session is None:
                return
            self._send_json({"logs": session.logger.entries[-5:]})
            return

        super().do_GET()

    @serialize_session_request
    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_json({"error": "Invalid Content-Length"}, status=400)
            return
        if content_len < 0 or content_len > MAX_REQUEST_BYTES:
            self._send_json({"error": "Request body is too large"}, status=413)
            return
        try:
            body_str = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        except UnicodeDecodeError:
            self._send_json({"error": "Request body must be UTF-8 JSON"}, status=400)
            return

        try:
            req_data = json.loads(body_str)
        except json.JSONDecodeError:
            self._send_json({"error": "Request body must be valid JSON"}, status=400)
            return
        if not isinstance(req_data, dict):
            self._send_json({"error": "Request body must be a JSON object"}, status=400)
            return

        session = self._get_session()
        if session is None:
            return

        if parsed.path == "/api/reset":
            session.accountant.reset()
            session.nist.used_seeds.clear()
            self._send_json({"message": "Budget accountant reset successfully", "accountant": session.accountant.get_status()})
            return

        if parsed.path == "/api/set_budget":
            try:
                new_tot_eps = float(req_data.get("total_epsilon", 5.0))
            except (TypeError, ValueError):
                self._send_json({"error": "Total epsilon must be a finite positive number"}, status=400)
                return
            if not math.isfinite(new_tot_eps) or not 0 < new_tot_eps <= 100:
                self._send_json({"error": "Total epsilon must be greater than 0 and at most 100"}, status=400)
                return
            # the per-query cap (session.nist.max_epsilon) is a separate setting and stays put
            session.accountant.set_budget(new_tot_eps)
            session.nist.used_seeds.clear()
            self._send_json({"message": f"Privacy accountant budget set to {new_tot_eps}", "accountant": session.accountant.get_status()})
            return

        if parsed.path == "/api/analyze_code":
            code_text = req_data.get("code", "")
            if not isinstance(code_text, str) or not code_text.strip():
                self._send_json({"error": "No Python code supplied"}, status=400)
                return
            if len(code_text) > MAX_CODE_CHARACTERS:
                self._send_json({"error": "Python source exceeds the hosted demo size limit"}, status=413)
                return

            static_report = analyze_python_code(
                code_text,
                max_epsilon=session.nist.max_epsilon,
                total_budget=session.accountant.total_epsilon,
            )

            # first diffprivlib mechanism the linter resolved; anything it couldn't
            # work out stays null rather than being guessed
            detected_params = None
            for dp_call in static_report.get("dp_calls", []):
                mechanism = _MECHANISM_BY_CLASS.get(dp_call.get("func"))
                if mechanism and dp_call.get("kind") == "mechanism":
                    params = dp_call.get("params", {})
                    detected_params = {
                        "mechanism": mechanism,
                        "line": dp_call.get("line"),
                        "epsilon": params.get("epsilon"),
                        "delta": params.get("delta"),
                        "sensitivity": params.get("sensitivity"),
                        "lower": params.get("lower"),
                        "upper": params.get("upper"),
                    }
                    break

            self._send_json({
                "static_analysis": static_report,
                "dynamic_execution": {
                    "execution_status": "DISABLED",
                    "stdout": "",
                    "runtime_error": "Submitted Python is analyzed statically and is never executed.",
                },
                "accountant": session.accountant.get_status(),
                "detected_params": detected_params,
                "symbol_table": static_report.get("symbol_table", {}),
            })
            return

        if parsed.path == "/api/execute_query":
            self._execute_query(session, req_data)
            return

        self.send_error(404, "Endpoint not found")

    def _execute_query(self, session, req_data):
        mechanism_type = req_data.get("mechanism", "laplace")
        if not isinstance(mechanism_type, str) or mechanism_type.lower() not in MECHANISMS:
            self._send_json({"error": f"Unknown mechanism. Supported: {', '.join(MECHANISMS)}"}, status=400)
            return
        mechanism_type = mechanism_type.lower()
        key, builder, uses_delta, integer_valued = MECHANISMS[mechanism_type]

        try:
            value = float(req_data.get("value", 42.0))
            epsilon = float(req_data.get("epsilon", 1.0))
            delta = float(req_data.get("delta", 1e-6)) if uses_delta else 0.0
            lower = float(req_data.get("lower", 0.0))
            upper = float(req_data.get("upper", 100.0))
        except (TypeError, ValueError):
            self._send_json({"error": "Query parameters must be numeric"}, status=400)
            return
        if not all(math.isfinite(number) for number in (value, epsilon, delta, lower, upper)):
            self._send_json({"error": "Query parameters must be finite numbers"}, status=400)
            return
        if lower >= upper:
            self._send_json({"error": "Lower bound must be less than upper bound"}, status=400)
            return
        if integer_valued and not all(float(number).is_integer() for number in (value, lower, upper)):
            self._send_json({"error": "The geometric mechanism needs an integer value and integer bounds"}, status=400)
            return
        seed_ok, seed = _optional_positive_int(req_data.get("seed"))
        size_ok, dataset_size = _optional_positive_int(req_data.get("dataset_size"))
        if not seed_ok or not size_ok:
            self._send_json({"error": "Seed and dataset size must be positive integers when given"}, status=400)
            return

        # we release one clamped value, so the sensitivity is the width of [L, U]
        clamped, out_of_bounds = session.nist.clamp_dataset_bounds([value], lower, upper)
        eff_val = int(clamped[0]) if integer_valued else float(clamped[0])
        sensitivity = upper - lower
        params = {
            "epsilon": epsilon, "delta": delta, "sensitivity": sensitivity,
            "lower": lower, "upper": upper, "seed": seed,
        }
        input_info = {
            "raw_input": value,
            "bounds": [lower, upper],
            "clamped_input": eff_val,
            "clamped_applied": bool(out_of_bounds),
            "sensitivity": sensitivity,
        }

        call = DPCall(
            key=key, epsilon=epsilon, delta=delta, dataset_size=dataset_size, seed=seed,
            accountant=session.accountant, nist=session.nist, logger=session.logger,
        )
        built = {}

        def target(v):
            # build the mechanism in here so our validation and budget checks run
            # before any diffprivlib code does
            mech, calc = builder(params)
            if mech.epsilon != call.epsilon or float(getattr(mech, "delta", 0.0) or 0.0) != call.delta:
                raise RuntimeError("mechanism parameters differ from the accounted parameters")
            built["calc"] = calc
            return mech.randomise(v)

        response = {
            "mechanism": mechanism_type,
            "target": key,
            "input": input_info,
            "max_query_epsilon": session.nist.max_epsilon,
        }
        try:
            result = run_dp_call(call, target, eff_val)
        except DPAdviceError as err:
            failed_stage = call.trace[-1]["stage"] if call.trace else "validate"
            response.update({
                "status": "FAILED" if isinstance(err, SanitizedExecutionError) else "BLOCKED",
                "stage_failed": failed_stage,
                "error": str(err),
            })
        else:
            calc = built["calc"]
            calc.update({
                "noise_drawn": float(result) - float(eff_val),
                "sensitivity": sensitivity,
                "clamped_input": eff_val,
            })
            response.update({
                "status": "SUCCESS",
                "final_result": result,
                "calculations": calc,
            })
        response["stages"] = call.trace
        response["accountant"] = session.accountant.get_status()
        self._send_json(response)

def run(port=8000):
    server_address = ('', port)
    httpd = ThreadingHTTPServer(server_address, DPAdviceHTTPHandler)
    httpd.daemon_threads = True
    print(f"[+] DP-Advice Web Dashboard running at http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    run(port)
