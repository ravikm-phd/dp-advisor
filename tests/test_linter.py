"""Linter tests. Each rule has one snippet that must trigger it and one that must not."""

import pytest
from dp_advice.analyzer.static_linter import analyze_python_code, RULES


def rules(code, **kwargs):
    return {f["rule_id"] for f in analyze_python_code(code, **kwargs)["findings"]}


HEADER = "import numpy as np\nimport diffprivlib.mechanisms as dp_mech\nimport diffprivlib.tools as dp_tools\n"

# rule -> (should fire, should not fire)
CASES = {
    "NIST-ERR-01": (
        "m = dp_mech.Laplace(epsilon=0.0, sensitivity=1.0)",
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)",
    ),
    "NIST-ERR-02": (
        "x = np.random.laplace(0, -1.0)",
        "import matplotlib.pyplot as plt\nplt.plot([1, 2], scale=-1)",
    ),
    "NIST-ERR-03": (
        "m = dp_mech.Laplace(epsilon=2.0, sensitivity=1.0)\na = m.randomise(1.0)\nb = m.randomise(1.0)",
        "m = dp_mech.Laplace(epsilon=2.0, sensitivity=1.0)\na = m.randomise(1.0)",
    ),
    "NIST-ERR-06": (
        "m = dp_mech.Laplace(epsilon=1.0, delta=1e-6, sensitivity=1.0)",
        "m = dp_mech.GaussianAnalytic(epsilon=1.0, delta=1e-6, sensitivity=1.0)",
    ),
    "NIST-ERR-07": (
        "import tensorflow_privacy\nopt = tensorflow_privacy.DPKerasSGDOptimizer(noise_multiplier=1.1, learning_rate=0.1)",
        "import tensorflow_privacy\nopt = tensorflow_privacy.DPKerasSGDOptimizer(l2_norm_clip=1.0, noise_multiplier=1.1)",
    ),
    "NIST-WARN-01": (
        "m = dp_mech.Laplace(epsilon=15.0, sensitivity=1.0)",
        "m = dp_mech.Laplace(epsilon=10.0, sensitivity=1.0)",
    ),
    "NIST-WARN-02": (
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0, random_state=42)",
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0, random_state=None)",
    ),
    "NIST-WARN-03": (
        "r = dp_tools.mean([1.0, 2.0], epsilon=1.0)",
        "r = dp_tools.mean([1.0, 2.0], epsilon=1.0, bounds=(0, 10))",
    ),
    "NIST-WARN-04": (
        "data = [1.0, 5.0]\nspread = np.max(data) - np.min(data)",
        "upper = 10.0\nlower = 0.0\nspread = upper - lower",
    ),
    "NIST-WARN-05": (
        "m = dp_mech.GaussianAnalytic(epsilon=1.0, delta=0.01, sensitivity=1.0)",
        "m = dp_mech.GaussianAnalytic(epsilon=1.0, delta=1e-6, sensitivity=1.0)",
    ),
    "NIST-WARN-07": (
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)",
        "m = dp_mech.Geometric(epsilon=1.0, sensitivity=1)",
    ),
    "NIST-WARN-08": (
        "import pandas as pd\ndf = pd.DataFrame()\nm = dp_mech.Laplace(epsilon=0.1, sensitivity=1.0)\n"
        "for name, group in df.groupby('city'):\n    out = m.randomise(1.0)",
        "import pandas as pd\ndf = pd.DataFrame()\nm = dp_mech.Laplace(epsilon=0.1, sensitivity=1.0)\n"
        "for name, group in df.groupby('city'):\n    pass\nout = m.randomise(1.0)",
    ),
    "NIST-WARN-09": (
        "import pandas as pd\ndf = pd.DataFrame()\ndf['name'] = 'Anonymous'",
        "label = 'Anonymous'",
    ),
    "NIST-WARN-12": (
        "data = [1.0, 2.0]\nr = dp_tools.mean(data, epsilon=1.0, bounds=(0, 10))\nprint(np.mean(data), r)",
        "data = [1.0, 2.0]\nr = dp_tools.mean(data, epsilon=1.0, bounds=(0, 10))\nprint(r)",
    ),
    "NIST-WARN-13": (
        "m = dp_mech.Laplace(epsilon=0.0001, sensitivity=1.0)",
        "m = dp_mech.Laplace(epsilon=0.1, sensitivity=1.0)",
    ),
    "NIST-WARN-21": (
        "m = dp_mech.GaussianAnalytic(epsilon=1.0, delta=1e-6, sensitivity=1.0)",
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)",
    ),
    "NIST-WARN-23": (
        "noisy = 5.0 + np.random.laplace(0, 1.0)",
        "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)\nnoisy = m.randomise(5.0)",
    ),
}


def test_every_implemented_rule_has_a_case():
    assert set(CASES) == set(RULES)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_rule_fires(rule):
    assert rule in rules(HEADER + CASES[rule][0], total_budget=3.0)


@pytest.mark.parametrize("rule", sorted(CASES))
def test_rule_does_not_fire(rule):
    assert rule not in rules(HEADER + CASES[rule][1], total_budget=3.0)


def test_names_are_resolved_through_imports_not_substrings():
    # having "laplace" in a function name doesn't make it a mechanism
    report = analyze_python_code("def my_laplace_plot(epsilon, scale):\n    pass\nmy_laplace_plot(epsilon=-1, scale=-1)")
    assert report["findings"] == [] and report["dp_calls_count"] == 0

    # same mechanism, four ways of importing it
    for code in (
        "from diffprivlib.mechanisms import Laplace\nm = Laplace(epsilon=0.0, sensitivity=1.0)",
        "from diffprivlib.mechanisms import Laplace as L\nm = L(epsilon=0.0, sensitivity=1.0)",
        "import diffprivlib\nm = diffprivlib.mechanisms.Laplace(epsilon=0.0, sensitivity=1.0)",
        "import diffprivlib.mechanisms\nm = diffprivlib.mechanisms.Laplace(epsilon=0.0, sensitivity=1.0)",
    ):
        assert "NIST-ERR-01" in rules(code), code


def test_custom_noise_is_found_through_dotted_names_and_generators():
    for code in (
        "import numpy as np\nx = np.random.laplace(0, 1.0)",
        "import numpy\nx = numpy.random.normal(0, 1.0)",
        "from numpy import random\nx = random.laplace(0, 1.0)",
        "import numpy as np\nrng = np.random.default_rng()\nx = rng.laplace(0, 1.0)",
        "import random\nx = random.gauss(0, 1.0)",
    ):
        assert "NIST-WARN-23" in rules(code), code
    assert "NIST-WARN-02" in rules("import numpy as np\nrng = np.random.default_rng(42)")
    assert "NIST-WARN-02" in rules("import numpy as np\nnp.random.seed(1)")


def test_symbol_table_and_parameters_are_reported():
    code = HEADER + "epsilon = 2.5\nsens = 4.0 / 2\nmech = dp_mech.Laplace(epsilon=epsilon, sensitivity=sens)\nout = mech.randomise(1.0)"
    report = analyze_python_code(code)
    assert report["symbol_table"]["epsilon"] == 2.5 and report["symbol_table"]["sens"] == 2.0
    constructor = next(c for c in report["dp_calls"] if c["kind"] == "mechanism")
    assert constructor["func"] == "diffprivlib.mechanisms.Laplace"
    assert constructor["params"] == {"epsilon": 2.5, "sensitivity": 2.0}
    assert report["cumulative_epsilon"] == 2.5


def test_unresolved_epsilon_is_reported_not_guessed():
    code = HEADER + "import os\neps = float(os.environ['EPS'])\nmech = dp_mech.Laplace(epsilon=eps, sensitivity=1.0)\nout = mech.randomise(1.0)"
    report = analyze_python_code(code, total_budget=1.0)
    assert report["unresolved_releases"] == 1 and report["cumulative_epsilon"] == 0.0
    assert "epsilon" not in next(c for c in report["dp_calls"] if c["kind"] == "mechanism")["params"] or \
        next(c for c in report["dp_calls"] if c["kind"] == "mechanism")["params"]["epsilon"] is None


def test_verdicts():
    clean = HEADER + "m = dp_mech.Geometric(epsilon=1.0, sensitivity=1)\nout = m.randomise(3)"
    assert analyze_python_code(clean)["verdict"] == "PASSED"
    # LOW is informational only
    low_only = HEADER + "m = dp_mech.Laplace(epsilon=1.0, sensitivity=1.0)\nout = m.randomise(3.0)"
    report = analyze_python_code(low_only)
    assert report["verdict"] == "PASSED" and report["severity_summary"]["LOW"] == 1
    assert analyze_python_code(HEADER + "x = np.random.laplace(0, 1.0)")["verdict"] == "WARNING"
    assert analyze_python_code(HEADER + "m = dp_mech.Laplace(epsilon=-1.0, sensitivity=1.0)")["verdict"] == "REJECTED"
    assert analyze_python_code("def broken(:")["verdict"] == "SYNTAX_ERROR"


def test_code_is_not_executed():
    report = analyze_python_code("import os\nos.environ['DP_ADVICE_LINTER_RAN'] = '1'")
    import os
    assert "DP_ADVICE_LINTER_RAN" not in os.environ and report["verdict"] == "PASSED"
