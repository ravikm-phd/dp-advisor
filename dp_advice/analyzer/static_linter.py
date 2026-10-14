"""Static checks for differential privacy code. Nothing is ever executed.

Calls are recognised by resolving imports and dotted names to full names
(dp_mech.Laplace -> diffprivlib.mechanisms.Laplace) rather than by looking for
"laplace" somewhere in a function name.

There are 17 rules (see RULES). advice_walkthrough.md says how each one relates to
NIST SP 800-226; page numbers are the printed ones. Thresholds and severities are
our defaults.

Limits worth knowing about: a single flat symbol table (no scopes, no control
flow), values are only resolved when they are literals or simple arithmetic, and a
release inside a loop counts once. A clean report doesn't mean the code is private.

The diffprivlib names were checked against diffprivlib 0.6.5. The OpenDP, PyDP,
TensorFlow Privacy and Opacus names come from those projects' docs and have not
been checked against installed copies.
"""

import ast
from typing import List, Dict, Any, Optional, Set, Tuple

# rule id -> (title, severity)
RULES: Dict[str, Tuple[str, str]] = {
    "NIST-ERR-01": ("Negative/Zero Epsilon", "CRITICAL"),
    "NIST-ERR-02": ("Invalid Scale Parameter", "CRITICAL"),
    "NIST-ERR-03": ("Privacy Budget Exhaustion", "CRITICAL"),
    "NIST-ERR-06": ("Delta Passed to Laplace Mechanism", "MEDIUM"),
    "NIST-ERR-07": ("DP-SGD Missing Per-Example Gradient Clipping", "CRITICAL"),
    "NIST-WARN-01": ("Large Epsilon", "HIGH"),
    "NIST-WARN-02": ("Fixed PRNG Seed", "MEDIUM"),
    "NIST-WARN-03": ("Missing Clipping Bounds", "HIGH"),
    "NIST-WARN-04": ("Data-Dependent Sensitivity", "MEDIUM"),
    "NIST-WARN-05": ("Large Delta", "HIGH"),
    "NIST-WARN-07": ("Floating-Point Noise", "LOW"),
    "NIST-WARN-08": ("Group-By Without Contribution Bounds", "MEDIUM"),
    "NIST-WARN-09": ("Naive De-Identification", "MEDIUM"),
    "NIST-WARN-12": ("Non-DP Release Alongside DP Outputs", "HIGH"),
    "NIST-WARN-13": ("Very Small Epsilon", "MEDIUM"),
    "NIST-WARN-21": ("L2 Sensitivity Required", "LOW"),
    "NIST-WARN-23": ("Custom Noise Implementation", "MEDIUM"),
}

MIN_USEFUL_EPSILON = 0.001
SUSPICIOUS_DELTA = 1e-5

_DIFFPRIVLIB_MECHANISMS = {
    "Binary", "Bingham", "Exponential", "ExponentialCategorical", "ExponentialHierarchical",
    "Gaussian", "GaussianAnalytic", "GaussianDiscrete", "Geometric", "GeometricFolded",
    "GeometricTruncated", "Laplace", "LaplaceBoundedDomain", "LaplaceBoundedNoise", "LaplaceFolded",
    "LaplaceTruncated", "PermuteAndFlip", "Snapping", "Staircase", "Uniform", "Vector",
}
_CONTINUOUS_LAPLACE = {"Laplace", "LaplaceBoundedDomain", "LaplaceBoundedNoise", "LaplaceFolded", "LaplaceTruncated"}
_CONTINUOUS_GAUSSIAN = {"Gaussian", "GaussianAnalytic"}
_TOOLS_NEEDING_BOUNDS = {
    "mean", "median", "nanmean", "nanstd", "nansum", "nanvar", "percentile", "quantile", "std", "sum", "var",
}
_TOOLS_NEEDING_RANGE = {"histogram", "histogram2d", "histogramdd"}
_TOOLS_OTHER = {"count_nonzero"}
_CUSTOM_NOISE = {
    "numpy.random.laplace", "numpy.random.normal", "random.gauss", "random.normalvariate",
}
_RNG_FACTORIES = {"numpy.random.default_rng", "numpy.random.RandomState", "numpy.random.Generator"}
_SEED_FUNCTIONS = {"numpy.random.seed", "random.seed"} | _RNG_FACTORIES
_EXACT_STATISTICS = {
    "sum", "min", "max",
    "numpy.mean", "numpy.sum", "numpy.median", "numpy.std", "numpy.var",
    "numpy.min", "numpy.max", "numpy.amin", "numpy.amax",
}
_MAX_FUNCTIONS = {"max", "numpy.max", "numpy.amax", "numpy.nanmax"}
_MIN_FUNCTIONS = {"min", "numpy.min", "numpy.amin", "numpy.nanmin"}
_PLACEHOLDER_STRINGS = {"anonymous", "unknown", "redacted", "xxx", "***", "n/a"}
_OPENDP_ALIASES = {
    "opendp.prelude.m.": "opendp.measurements.",
    "opendp.prelude.t.": "opendp.transformations.",
    "opendp.m.": "opendp.measurements.",
    "opendp.t.": "opendp.transformations.",
}


class DPASTVisitor(ast.NodeVisitor):
    def __init__(self, max_epsilon: float = 10.0, total_budget: Optional[float] = None):
        self.max_epsilon = max_epsilon
        self.total_budget = total_budget
        self.findings: List[Dict[str, Any]] = []
        self.dp_calls_found: List[Dict[str, Any]] = []
        self.symbol_table: Dict[str, Any] = {}
        self.imports: Dict[str, str] = {}
        self.var_types: Dict[str, str] = {}
        self.var_params: Dict[str, Dict[str, Any]] = {}
        self.detected_dataset_size: int = 0
        self.cumulative_epsilon: float = 0.0
        self.unresolved_releases: int = 0
        self._budget_reported = False
        self._seen: Set[Tuple[str, int]] = set()
        self._release_nodes: Set[int] = set()
        self._outer_loops: List[ast.AST] = []
        self._loop_depth = 0
        self._print_candidates: List[Tuple[int, str, str]] = []

    def _add(self, rule: str, line: int, message: str, severity: Optional[str] = None):
        if (rule, line) in self._seen:
            return
        self._seen.add((rule, line))
        title, default_severity = RULES[rule]
        self.findings.append({
            "rule": f"{rule} ({title})",
            "rule_id": rule,
            "severity": severity or default_severity,
            "line": line,
            "message": message,
        })

    def _dotted(self, node: ast.AST) -> Optional[str]:
        """Full dotted name an expression refers to, or None if we can't tell."""
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            root = node.id
            if root in self.var_types:
                base = self.var_types[root]
            elif root in self.imports:
                base = self.imports[root]
            else:
                base = root
        elif isinstance(node, ast.Call):
            base = self._dotted(node.func)
            if base is None:
                return None
        else:
            return None
        name = ".".join([base] + list(reversed(parts)))
        for alias, target in _OPENDP_ALIASES.items():
            if name.startswith(alias):
                name = target + name[len(alias):]
        return name

    def _eval(self, node: Optional[ast.AST]) -> Any:
        """Value of a literal, a known variable or simple arithmetic; None if unknown."""
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.symbol_table.get(node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            val = self._eval(node.operand)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return -val if isinstance(node.op, ast.USub) else val
            return None
        if isinstance(node, ast.BinOp):
            left, right = self._eval(node.left), self._eval(node.right)
            if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (left, right)):
                try:
                    if isinstance(node.op, ast.Add):
                        return left + right
                    if isinstance(node.op, ast.Sub):
                        return left - right
                    if isinstance(node.op, ast.Mult):
                        return left * right
                    if isinstance(node.op, ast.Div):
                        return left / right
                    if isinstance(node.op, ast.Pow) and abs(right) <= 64:
                        return left ** right
                except (ZeroDivisionError, OverflowError):
                    return None
            return None
        if isinstance(node, (ast.Tuple, ast.List)):
            values = [self._eval(e) for e in node.elts]
            return values if all(v is not None for v in values) else None
        return None

    @staticmethod
    def _is_num(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def _arg(self, node: ast.Call, name: str, position: Optional[int] = None) -> Optional[ast.AST]:
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        if position is not None and len(node.args) > position and not isinstance(node.args[position], ast.Starred):
            return node.args[position]
        return None

    def _has_kw(self, node: ast.Call, *names: str) -> bool:
        return any(kw.arg in names for kw in node.keywords)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.imports[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.imports[root] = root

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    self.imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def visit_Assign(self, node: ast.Assign):
        self.generic_visit(node)

        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        value = self._eval(node.value)
        for name in names:
            # the name now points at something else
            self.var_types.pop(name, None)
            self.var_params.pop(name, None)
            if value is not None:
                self.symbol_table[name] = value
            else:
                self.symbol_table.pop(name, None)

        if isinstance(node.value, ast.Call):
            qualified = self._dotted(node.value.func)
            if qualified and self._is_tracked_constructor(qualified):
                params = {kw.arg: self._eval(kw.value) for kw in node.value.keywords if kw.arg}
                for name in names:
                    self.var_types[name] = qualified
                    self.var_params[name] = params

        # guess the dataset size from list literals: data = [...] or np.array([...])
        if isinstance(node.value, ast.List):
            self.detected_dataset_size = max(self.detected_dataset_size, len(node.value.elts))
        elif isinstance(node.value, ast.Call):
            for arg in node.value.args:
                if isinstance(arg, ast.List):
                    self.detected_dataset_size = max(self.detected_dataset_size, len(arg.elts))

        # NIST-WARN-09, e.g. df['name'] = 'Anonymous'
        if any(isinstance(t, ast.Subscript) for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                if node.value.value.strip().lower() in _PLACEHOLDER_STRINGS:
                    self._add("NIST-WARN-09", node.lineno,
                              "Overwriting a column with a placeholder string is de-identification, not differential "
                              "privacy; de-identified data remains open to linking attacks (NIST SP 800-226 Sec 1.1, Pg 6-7).")

    def _is_tracked_constructor(self, qualified: str) -> bool:
        module, _, name = qualified.rpartition(".")
        return (
            (module == "diffprivlib.mechanisms" and name in _DIFFPRIVLIB_MECHANISMS)
            or module.startswith("pydp.algorithms")
            or qualified in _RNG_FACTORIES
        )

    # loops: NIST-WARN-08 is decided later, in finalize()

    def _visit_loop(self, node: ast.AST):
        if self._loop_depth == 0:
            self._outer_loops.append(node)
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    visit_For = _visit_loop
    visit_While = _visit_loop
    visit_ListComp = _visit_loop
    visit_DictComp = _visit_loop
    visit_SetComp = _visit_loop
    visit_GeneratorExp = _visit_loop

    def visit_BinOp(self, node: ast.BinOp):
        # NIST-WARN-04: max(data) - min(data)
        if isinstance(node.op, ast.Sub) and self._is_extreme(node.left, _MAX_FUNCTIONS, "max") \
                and self._is_extreme(node.right, _MIN_FUNCTIONS, "min"):
            self._add("NIST-WARN-04", node.lineno,
                      "A range computed as max - min of the data depends on the private data. Clipping bounds must be "
                      "given without looking at the data or be estimated with a DP mechanism "
                      "(NIST SP 800-226 Sec 3.4.2 & 3.4.4, Pg 43, 44).")
        self.generic_visit(node)

    def _is_extreme(self, node: ast.AST, functions: Set[str], method: str) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if self._dotted(node.func) in functions:
            return True
        return isinstance(node.func, ast.Attribute) and node.func.attr == method and not node.args

    def visit_Call(self, node: ast.Call):
        qualified = self._dotted(node.func) or ""
        module, _, name = qualified.rpartition(".")

        if module == "diffprivlib.mechanisms" and name in _DIFFPRIVLIB_MECHANISMS:
            self._check_mechanism_constructor(node, qualified, name)
        elif name == "randomise" and self._is_mechanism_class(module):
            self._record_release(node, qualified, self._instance_epsilon(node))
        elif module == "diffprivlib.tools" and name in (_TOOLS_NEEDING_BOUNDS | _TOOLS_NEEDING_RANGE | _TOOLS_OTHER):
            self._check_diffprivlib_tool(node, qualified, name)
        elif module.startswith("diffprivlib.models") and self._has_kw(node, "epsilon"):
            params = self._check_privacy_params(node, qualified, "model")
            self._record_release(node, qualified, params.get("epsilon"))
        elif module.startswith("pydp.algorithms") and name[:1].isupper():
            self._check_pydp_constructor(node, qualified, name)
        elif module.startswith("pydp.algorithms") and name in ("result", "quick_result"):
            self._record_release(node, qualified, self._instance_epsilon(node))
        elif module == "opendp.measurements" and name.startswith(("make_", "then_")) \
                and any(term in name for term in ("laplace", "gaussian", "geometric")):
            self._check_opendp_noise(node, qualified, name)
        elif qualified in _CUSTOM_NOISE or (module in _RNG_FACTORIES and name in ("laplace", "normal")):
            self._check_custom_noise(node, qualified)
        elif self._is_dpsgd(module, name):
            self._check_dpsgd(node, qualified, name)

        if qualified in _SEED_FUNCTIONS:
            seed = self._eval(self._arg(node, "seed", 0))
            if isinstance(seed, int) and not isinstance(seed, bool):
                self._add_seed_finding(node.lineno, seed)

        if qualified == "print" or (isinstance(node.func, ast.Attribute) and node.func.attr == "write"):
            self._collect_print_candidate(node)

        self.generic_visit(node)

    @staticmethod
    def _is_mechanism_class(qualified: str) -> bool:
        module, _, name = qualified.rpartition(".")
        return module == "diffprivlib.mechanisms" and name in _DIFFPRIVLIB_MECHANISMS

    def _instance_epsilon(self, node: ast.Call) -> Any:
        """Epsilon of the mechanism a method is called on (the `mech` in mech.randomise(x))."""
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if isinstance(receiver, ast.Name):
            return self.var_params.get(receiver.id, {}).get("epsilon")
        if isinstance(receiver, ast.Call):
            return self._eval(self._arg(receiver, "epsilon"))
        return None

    def _record_call(self, node: ast.Call, qualified: str, kind: str, params: Dict[str, Any]):
        self.dp_calls_found.append({
            "line": node.lineno,
            "func": qualified,
            "kind": kind,
            "params": {k: v for k, v in params.items() if _json_safe(v)},
        })

    def _record_release(self, node: ast.Call, qualified: str, epsilon: Any):
        self._release_nodes.add(id(node))
        if not any(c["line"] == node.lineno and c["func"] == qualified for c in self.dp_calls_found):
            self._record_call(node, qualified, "release", {"epsilon": epsilon})
        if not self._is_num(epsilon) or epsilon <= 0:
            self.unresolved_releases += 1
            return
        self.cumulative_epsilon += epsilon
        # NIST-ERR-03
        if self.total_budget is not None and not self._budget_reported \
                and self.cumulative_epsilon > self.total_budget + 1e-9:
            self._budget_reported = True
            self._add("NIST-ERR-03", node.lineno,
                      f"Cumulative epsilon of the releases found ({self.cumulative_epsilon:.4g}) exceeds the privacy budget "
                      f"({self.total_budget:.4g}) under sequential composition (NIST SP 800-226 Sec 2.1.2 & 2.2, Pg 12, 14-15). "
                      "Releases inside loops are counted once.")

    def _check_privacy_params(self, node: ast.Call, qualified: str, kind: str) -> Dict[str, Any]:
        params = {kw.arg: self._eval(kw.value) for kw in node.keywords if kw.arg}
        self._record_call(node, qualified, kind, params)

        eps = params.get("epsilon")
        if self._is_num(eps):
            if eps <= 0:
                self._add("NIST-ERR-01", node.lineno,
                          f"Invalid privacy budget epsilon={eps} (NIST SP 800-226 Sec 2.1.1 & App B.1, Pg 11, 75). "
                          "Must be strictly positive (> 0).")
            elif eps < MIN_USEFUL_EPSILON:
                self._add("NIST-WARN-13", node.lineno,
                          f"Epsilon={eps} is below the DP-Advice default threshold of {MIN_USEFUL_EPSILON}; the noise will "
                          "likely swamp the result (see NIST SP 800-226 Sec 2.2 & 3.2, Pg 13, 31 on the privacy-utility trade-off).")
            elif eps > self.max_epsilon:
                self._add("NIST-WARN-01", node.lineno,
                          f"Weak privacy budget epsilon={eps} exceeds the configured threshold ({self.max_epsilon}). "
                          "NIST SP 800-226 sets no cap, but notes that epsilon of 10 or greater can leave outliers "
                          "vulnerable (Sec 2.2, Pg 14).")

        delta = params.get("delta")
        if self._is_num(delta) and delta > SUSPICIOUS_DELTA:
            extra = ""
            n = self.detected_dataset_size
            if n > 1 and delta > 1.0 / (n * n):
                extra = f" For the detected dataset size n={n}, 1/n^2 = {1.0 / (n * n):.3g}."
            self._add("NIST-WARN-05", node.lineno,
                      f"Large delta={delta} (NIST SP 800-226 Sec 2.3, Pg 16-17). NIST recommends delta <= 1/n^2 and treats "
                      f"values above 1e-5 as suspicious; a large delta permits catastrophic failure.{extra}")

        seed = params.get("random_state", params.get("seed"))
        if isinstance(seed, int) and not isinstance(seed, bool):
            self._add_seed_finding(node.lineno, seed)
        return params

    def _add_seed_finding(self, line: int, seed: int):
        self._add("NIST-WARN-02", line,
                  f"Hardcoded PRNG seed ({seed}). A fixed seed makes the noise reproducible, so it can be subtracted. "
                  "(General RNG hygiene; NIST SP 800-226 does not discuss seeds.)")

    def _check_mechanism_constructor(self, node: ast.Call, qualified: str, name: str):
        params = self._check_privacy_params(node, qualified, "mechanism")

        if name in _CONTINUOUS_LAPLACE:
            delta = params.get("delta")
            if self._is_num(delta) and delta > 0:
                self._add("NIST-ERR-06", node.lineno,
                          f"delta={delta} passed to a Laplace mechanism. The standard Laplace mechanism provides "
                          "(epsilon, 0)-DP (NIST SP 800-226 App B.2, Pg 76); with delta > 0 the guarantee is "
                          "approximate DP. Confirm this is intended.")

        if name in _CONTINUOUS_LAPLACE or name in _CONTINUOUS_GAUSSIAN:
            self._add("NIST-WARN-07", node.lineno,
                      "Continuous noise on floating-point values can leak through the set of representable outputs "
                      "(NIST SP 800-226 Sec 4.3 & App B.7, Pg 58-59, 79). Confirm that the library version in use "
                      "mitigates this, or use a discrete or snapping mechanism.")

        if name in _CONTINUOUS_GAUSSIAN or name == "GaussianDiscrete":
            self._add("NIST-WARN-21", node.lineno,
                      "The Gaussian mechanism is calibrated to L2 sensitivity (NIST SP 800-226 Sec 3.1 & App B.2, Pg 30, 75-76). "
                      "Check that the sensitivity passed is an L2 bound.")

    def _check_diffprivlib_tool(self, node: ast.Call, qualified: str, name: str):
        params = self._check_privacy_params(node, qualified, "tool")
        needed = "range" if name in _TOOLS_NEEDING_RANGE else "bounds" if name in _TOOLS_NEEDING_BOUNDS else None
        if needed and not self._has_kw(node, needed):
            self._add("NIST-WARN-03", node.lineno,
                      f"{qualified} called without '{needed}'. Without fixed bounds the sensitivity is taken from the "
                      "data, which is not differentially private (NIST SP 800-226 Sec 3.4.2 & App B.4, Pg 43, 77).")
        epsilon = params.get("epsilon") if self._has_kw(node, "epsilon") else 1.0  # diffprivlib.tools default
        self._record_release(node, qualified, epsilon)

    def _check_pydp_constructor(self, node: ast.Call, qualified: str, name: str):
        self._check_privacy_params(node, qualified, "mechanism")
        if name.startswith("Bounded") and not (self._has_kw(node, "lower_bound") and self._has_kw(node, "upper_bound")):
            self._add("NIST-WARN-03", node.lineno,
                      f"{qualified} constructed without both 'lower_bound' and 'upper_bound'. Clipping bounds must be "
                      "fixed in advance or estimated privately (NIST SP 800-226 Sec 3.4.2 & App B.4, Pg 43, 77).")

    def _check_scale(self, node: ast.Call, scale_node: Optional[ast.AST]):
        scale = self._eval(scale_node)
        if self._is_num(scale) and scale <= 0:
            self._add("NIST-ERR-02", node.lineno,
                      f"Invalid noise scale={scale} (NIST SP 800-226 App B.2, Pg 76). Scale must be strictly positive (> 0).")
        return scale

    def _check_opendp_noise(self, node: ast.Call, qualified: str, name: str):
        scale = self._check_scale(node, self._arg(node, "scale"))
        self._record_call(node, qualified, "mechanism", {"scale": scale})
        if "laplace" in name or "gaussian" in name:
            self._add("NIST-WARN-07", node.lineno,
                      "Laplace/Gaussian noise on floating-point values can leak through the set of representable outputs "
                      "(NIST SP 800-226 Sec 4.3 & App B.7, Pg 58-59, 79). Confirm that the library version in use mitigates this.")

    def _check_custom_noise(self, node: ast.Call, qualified: str):
        scale_name = "sigma" if qualified.startswith("random.") else "scale"
        scale = self._check_scale(node, self._arg(node, scale_name, 1))
        self._record_call(node, qualified, "custom_noise", {"scale": scale})
        self._release_nodes.add(id(node))
        self._add("NIST-WARN-23", node.lineno,
                  f"Noise drawn directly with {qualified}. Hand-written mechanisms commonly miss floating-point and "
                  "sensitivity issues; prefer a maintained DP library (NIST SP 800-226 Sec 3.4, 4.3 & App B.7, Pg 40, 58, 79).")

    @staticmethod
    def _is_dpsgd(module: str, name: str) -> bool:
        if module.split(".")[0] == "tensorflow_privacy" and name.startswith("DP") and name.endswith("Optimizer"):
            return True
        return module.split(".")[0] == "opacus" and name in ("make_private", "make_private_with_epsilon")

    def _check_dpsgd(self, node: ast.Call, qualified: str, name: str):
        self._record_call(node, qualified, "dp_sgd", {})
        clip_kw = "l2_norm_clip" if name.endswith("Optimizer") else "max_grad_norm"
        if not self._has_kw(node, clip_kw):
            self._add("NIST-ERR-07", node.lineno,
                      f"{qualified} called without '{clip_kw}'. DP-SGD needs a per-example gradient clipping bound "
                      "(NIST SP 800-226 Sec 3.5 & App B.6, Pg 44, 79).")

    def _collect_print_candidate(self, node: ast.Call):
        worst: Optional[Tuple[str, str]] = None
        for arg in node.args:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call):
                    q = self._dotted(sub.func)
                    if q in _EXACT_STATISTICS:
                        worst = ("HIGH", f"an exact statistic ({q})")
                    elif q == "len" and worst is None:
                        worst = ("MEDIUM", "the exact dataset size (len)")
                elif isinstance(sub, ast.Attribute) and sub.attr in ("shape", "size") and worst is None:
                    worst = ("MEDIUM", f"the exact dataset size (.{sub.attr})")
        if worst:
            self._print_candidates.append((node.lineno, worst[0], worst[1]))

    def finalize(self):
        if self.dp_calls_found:
            for line, severity, what in self._print_candidates:
                note = ""
                if severity == "MEDIUM":
                    note = " This is acceptable only if the dataset size is public (bounded DP, Sec 2.4.1, Pg 21)."
                self._add("NIST-WARN-12", line,
                          f"The script outputs {what} without noise alongside DP results. DP does not protect other "
                          f"releases from the same data (NIST SP 800-226 Sec 2.6, Pg 27-28).{note}", severity)

        for loop in self._outer_loops:
            has_groupby = False
            has_release = False
            for sub in ast.walk(loop):
                if isinstance(sub, ast.Call):
                    if isinstance(sub.func, ast.Attribute) and sub.func.attr == "groupby":
                        has_groupby = True
                    if id(sub) in self._release_nodes:
                        has_release = True
            if has_groupby and has_release:
                self._add("NIST-WARN-08", getattr(loop, "lineno", 1),
                          "A DP release is made per group inside a group-by loop. If one person can appear in several "
                          "groups, their contribution must be bounded or the sensitivity scaled "
                          "(NIST SP 800-226 Sec 2.4.2 & App B.3, Pg 21-25, 76).")

        self.findings.sort(key=lambda f: f["line"])


def _json_safe(value: Any) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, list):
        return all(_json_safe(v) for v in value)
    return False


def _error_report(rule: str, line: int, message: str) -> Dict[str, Any]:
    return {
        "verdict": "SYNTAX_ERROR",
        "findings": [{"rule": rule, "rule_id": rule, "severity": "CRITICAL", "line": line, "message": message}],
        "dp_calls_count": 0,
        "dp_calls": [],
        "severity_summary": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "detected_dataset_size": 0,
        "symbol_table": {},
        "cumulative_epsilon": 0.0,
        "unresolved_releases": 0,
    }


def analyze_python_code(code_str: str, max_epsilon: float = 10.0, total_budget: Optional[float] = None) -> Dict[str, Any]:
    """Lint Python source without running it.

    max_epsilon: per-call epsilon above which NIST-WARN-01 fires.
    total_budget: if set, NIST-ERR-03 fires once the summed epsilon of the releases
        found goes past it.

    Verdict is REJECTED on any CRITICAL or HIGH finding, WARNING on MEDIUM, else
    PASSED. LOW findings are informational.
    """
    try:
        tree = ast.parse(code_str)
    except SyntaxError as se:
        return _error_report("PYTHON-SYNTAX-ERROR", se.lineno or 1, f"Python Syntax Error: {se.msg}")
    except (ValueError, RecursionError, MemoryError) as ex:
        return _error_report("PYTHON-PARSE-ERROR", 1, f"Source could not be parsed: {type(ex).__name__}")

    visitor = DPASTVisitor(max_epsilon=max_epsilon, total_budget=total_budget)
    try:
        visitor.visit(tree)
        visitor.finalize()
    except RecursionError:
        return _error_report("PYTHON-PARSE-ERROR", 1, "Source is too deeply nested to analyze.")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in visitor.findings:
        severity_counts[f["severity"]] += 1

    verdict = "PASSED"
    if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
        verdict = "REJECTED"
    elif severity_counts["MEDIUM"] > 0:
        verdict = "WARNING"

    symbol_table = {k: v for k, v in list(visitor.symbol_table.items())[:200] if _json_safe(v)}

    return {
        "verdict": verdict,
        "findings": visitor.findings,
        "dp_calls_count": len(visitor.dp_calls_found),
        "dp_calls": visitor.dp_calls_found,
        "severity_summary": severity_counts,
        "detected_dataset_size": visitor.detected_dataset_size,
        "symbol_table": symbol_table,
        "cumulative_epsilon": visitor.cumulative_epsilon,
        "unresolved_releases": visitor.unresolved_releases,
    }
