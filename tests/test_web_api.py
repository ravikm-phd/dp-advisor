"""Web API tests against a real server on a throwaway port."""

import json
import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))
import app as web_app  # noqa: E402


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), web_app.DPAdviceHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def api(base_url):
    session = str(uuid.uuid4())

    def call(path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            base_url + path, data=data, method="POST" if data is not None else "GET",
            headers={"X-DP-Advice-Session": session, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())
    return call


def query(**overrides):
    payload = {"mechanism": "laplace", "value": 42, "epsilon": 1.0, "lower": 0, "upper": 100}
    payload.update(overrides)
    return payload


def test_successful_query_runs_the_real_pipeline(api):
    status, body = api("/api/execute_query", query())
    assert status == 200 and body["status"] == "SUCCESS"
    assert [s["stage"] for s in body["stages"]] == ["validate", "reserve", "target", "after"]
    assert body["target"] == "diffprivlib.mechanisms.Laplace.randomise"
    assert body["calculations"]["param_value"] == pytest.approx(100.0)
    assert body["calculations"]["noise_drawn"] == pytest.approx(body["final_result"] - 42.0)
    assert body["accountant"]["consumed_epsilon"] == pytest.approx(1.0)

    _, logs = api("/api/logs")
    assert logs["logs"][-1]["target"] == "diffprivlib.mechanisms.Laplace.randomise"
    assert logs["logs"][-1]["status"] == "SUCCESS"


@pytest.mark.parametrize("mechanism,extra", [
    ("gaussian", {"epsilon": 2.0, "delta": 1e-6}),
    ("geometric", {}),
    ("snapping", {}),
])
def test_other_mechanisms(api, mechanism, extra):
    status, body = api("/api/execute_query", query(mechanism=mechanism, **extra))
    assert status == 200 and body["status"] == "SUCCESS", body
    assert isinstance(body["final_result"], (int, float))
    if mechanism == "gaussian":
        assert body["accountant"]["consumed_delta"] == pytest.approx(1e-6)
    if mechanism == "geometric":
        assert float(body["final_result"]).is_integer()
    if mechanism == "snapping":
        assert 0 <= body["final_result"] <= 100


def test_removed_mechanisms_are_rejected(api):
    for name in ("exponential", "advanced_composition", "subsampling"):
        status, body = api("/api/execute_query", query(mechanism=name))
        assert status == 400 and "error" in body


def test_validation_blocks_without_consuming(api):
    status, body = api("/api/execute_query", query(epsilon=50.0))
    assert body["status"] == "BLOCKED" and body["stage_failed"] == "validate"
    assert body["accountant"]["consumed_epsilon"] == 0.0


def test_budget_exhaustion_is_reported_by_the_reserve_stage(api):
    api("/api/set_budget", {"total_epsilon": 1.0})
    assert api("/api/execute_query", query(epsilon=0.75))[1]["status"] == "SUCCESS"
    _, body = api("/api/execute_query", query(epsilon=0.75))
    assert body["status"] == "BLOCKED" and body["stage_failed"] == "reserve"
    assert "budget" in body["error"].lower()
    assert body["accountant"]["consumed_epsilon"] == pytest.approx(0.75)


def test_budget_and_per_query_cap_are_separate(api):
    _, body = api("/api/set_budget", {"total_epsilon": 20.0})
    assert body["accountant"]["total_epsilon"] == 20.0
    _, status = api("/api/status")
    assert status["max_query_epsilon"] == 10.0
    assert api("/api/execute_query", query(epsilon=15.0))[1]["stage_failed"] == "validate"
    assert api("/api/execute_query", query(epsilon=10.0))[1]["status"] == "SUCCESS"


def test_delta_budget_and_dataset_size(api):
    _, body = api("/api/execute_query", query(mechanism="gaussian", delta=1e-6, dataset_size=10000))
    assert body["status"] == "BLOCKED" and "1/n^2" in body["error"]
    _, body = api("/api/execute_query", query(mechanism="gaussian", delta=0.5))
    assert body["status"] == "BLOCKED" and body["stage_failed"] == "reserve" and "delta" in body["error"]


def test_seed_is_used_and_reuse_is_blocked(api):
    _, first = api("/api/execute_query", query(seed=123))
    assert first["status"] == "SUCCESS"
    _, second = api("/api/execute_query", query(seed=123))
    assert second["status"] == "BLOCKED" and "Seed 123" in second["error"]


def test_geometric_requires_integers(api):
    status, body = api("/api/execute_query", query(mechanism="geometric", value=4.5))
    assert status == 400 and "integer" in body["error"]


def test_analyze_code_reports_real_parameters(api):
    code = "import diffprivlib.mechanisms as dp_mech\nepsilon = 2.5\nmech = dp_mech.Laplace(epsilon=epsilon, sensitivity=4.0)\nout = mech.randomise(1.0)\n"
    status, body = api("/api/analyze_code", {"code": code})
    assert status == 200
    assert body["dynamic_execution"]["execution_status"] == "DISABLED"
    assert body["symbol_table"] == {"epsilon": 2.5}
    params = body["detected_params"]
    assert params["mechanism"] == "laplace" and params["epsilon"] == 2.5 and params["sensitivity"] == 4.0
    assert params["lower"] is None and params["upper"] is None
    assert "calculations" not in body

    # no mechanism in the code -> no made-up parameters
    _, body = api("/api/analyze_code", {"code": "x = 1\n"})
    assert body["detected_params"] is None


def test_session_header_is_required(base_url):
    try:
        urllib.request.urlopen(base_url + "/api/status", timeout=10)
        assert False, "expected HTTP 400"
    except urllib.error.HTTPError as err:
        assert err.code == 400


def fetch_status(base_url, path):
    # http.client sends the path exactly as written; urllib would be fine too, but this makes it explicit
    import http.client
    host, port = base_url.replace("http://", "").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_index_and_static_files_are_served(base_url):
    for path in ("/", "/index.html", "/static/app.js", "/static/style.css", "/static/app.js?v=1", "/healthz"):
        assert fetch_status(base_url, path)[0] == 200, path


@pytest.mark.parametrize("path", [
    "/static/../app.py",
    "/static/../../requirements.txt",
    "/static/../../../../../../etc/passwd",
    "/static/%2e%2e/app.py",
    "/static/..%2fapp.py",
    "/static/",
    "/static",
    "/web/app.py",
    "/dp_advice/",
    "/dp_advice/__init__.py",
    "/requirements.txt",
    "/audit_logs/dp_compliance_audit.jsonl",
    "/templates/index.html",
    "/static/app.js/../../app.py",
    "/static/%00",
])
def test_nothing_else_is_served(base_url, path):
    status, body = fetch_status(base_url, path)
    assert status == 404, (path, status)
    assert b"DPAdviceHTTPHandler" not in body and b"root:" not in body
