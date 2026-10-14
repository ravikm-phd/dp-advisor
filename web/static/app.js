document.addEventListener("DOMContentLoaded", () => {
  const apiBase = (window.DP_ADVICE_API_BASE || "").replace(/\/+$/, "");
  const sessionId = getSessionId();
  let maxQueryEpsilon = 10.0;

  function getSessionId() {
    const storageKey = "dp-advice-session";
    try {
      let id = localStorage.getItem(storageKey);
      if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(storageKey, id);
      }
      return id;
    } catch (err) {
      return crypto.randomUUID();
    }
  }

  function apiFetch(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("X-DP-Advice-Session", sessionId);
    return fetch(`${apiBase}${path}`, { ...options, headers });
  }

  // anything from the server or from user code goes through this before it lands in innerHTML
  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function fmt(value, digits = 4) {
    return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "n/a";
  }

  const queryForm = document.getElementById("query-form");
  const resetBtn = document.getElementById("reset-budget-btn");
  const exhaustBtn = document.getElementById("btn-trigger-exhaust");

  const selectMechanism = document.getElementById("select-mechanism");
  const groupDelta = document.getElementById("group-delta");
  const mechanismBadgeLabel = document.getElementById("mechanism-badge-label");

  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      document.body.classList.toggle("light-theme");
      const isLight = document.body.classList.contains("light-theme");
      themeToggleBtn.innerHTML = isLight ? "🌙 Dark Mode" : "☀️ Light Mode";
      localStorage.setItem("dp_theme", isLight ? "light" : "dark");
    });

    if (localStorage.getItem("dp_theme") === "light") {
      document.body.classList.add("light-theme");
      themeToggleBtn.innerHTML = "🌙 Dark Mode";
    }
  }

  const mathScaleBox = document.getElementById("math-scale-box");
  const mathLaplaceBox = document.getElementById("math-laplace-box");
  const formulaParamTitle = document.getElementById("formula-param-title");
  const formulaMechanismTitle = document.getElementById("formula-mechanism-title");

  const metricConsumed = document.getElementById("metric-consumed");
  const metricRemaining = document.getElementById("metric-remaining");
  const metricQueries = document.getElementById("metric-queries");
  const progressBarFill = document.getElementById("progress-bar-fill");
  const progressPercentLbl = document.getElementById("progress-percent-lbl");

  const pipelineContainer = document.getElementById("pipeline-flow-container");
  const logTableBody = document.getElementById("log-table-body");

  const calcClampingSub = document.getElementById("calc-clamping-sub");
  const calcScaleSub = document.getElementById("calc-scale-sub");
  const calcLaplaceSub = document.getElementById("calc-laplace-sub");
  const calcRoundingSub = document.getElementById("calc-rounding-sub");
  const ROUNDING_NOTE = "Step 2^-40. A coarsening step only; not a floating-point attack mitigation.";

  const codeEditor = document.getElementById("code-editor");
  const lineNumbers = document.getElementById("line-numbers");
  const fileUploadInput = document.getElementById("file-upload-input");
  const btnAnalyzeCode = document.getElementById("btn-analyze-code");
  const btnLoadValidSample = document.getElementById("btn-load-valid-sample");
  const btnLoadVulnerableSample = document.getElementById("btn-load-vulnerable-sample");
  const codeAnalysisResults = document.getElementById("code-analysis-results");
  const resultBanner = document.getElementById("result-banner");
  const resultStatus = document.getElementById("result-status");
  const resultSummaryText = document.getElementById("result-summary-text");
  const staticFindingsList = document.getElementById("static-findings-list");
  const dynamicStdoutContainer = document.getElementById("dynamic-stdout-container");

  function updateLineNumbers() {
    if (!lineNumbers || !codeEditor) return;
    const linesCount = codeEditor.value.split("\n").length;
    const nums = [];
    for (let i = 1; i <= linesCount; i++) {
      nums.push(i);
    }
    lineNumbers.innerHTML = nums.join("<br>");
  }

  if (codeEditor && lineNumbers) {
    codeEditor.addEventListener("input", updateLineNumbers);
    codeEditor.addEventListener("scroll", () => {
      lineNumbers.scrollTop = codeEditor.scrollTop;
    });
    updateLineNumbers();
  }

  // give the KaTeX script a moment to load
  setTimeout(renderKaTeXElements, 100);

  fetchStatus();
  fetchLogs();

  selectMechanism.addEventListener("change", () => {
    updateFormulaCardHeaders(selectMechanism.value);
  });

  function updateFormulaCardHeaders(mech) {
    groupDelta.style.display = mech === "gaussian" ? "block" : "none";

    if (mech === "gaussian") {
      mechanismBadgeLabel.textContent = "Analytic Gaussian Mechanism Active";
      formulaParamTitle.textContent = "2. Gaussian Standard Deviation (σ)";
      formulaMechanismTitle.textContent = "3. Gaussian Noisy Release";
      mathScaleBox.setAttribute("data-tex", "\\Phi\\left(\\tfrac{\\Delta_2}{2\\sigma} - \\tfrac{\\epsilon\\sigma}{\\Delta_2}\\right) - e^{\\epsilon}\\,\\Phi\\left(-\\tfrac{\\Delta_2}{2\\sigma} - \\tfrac{\\epsilon\\sigma}{\\Delta_2}\\right) \\le \\delta");
      mathLaplaceBox.setAttribute("data-tex", "\\tilde{y} = x_{\\text{clamped}} + \\mathcal{N}\\left(0, \\sigma^2\\right)");
    } else if (mech === "geometric") {
      mechanismBadgeLabel.textContent = "Geometric Mechanism Active";
      formulaParamTitle.textContent = "2. Two-Sided Geometric Distribution";
      formulaMechanismTitle.textContent = "3. Integer Noisy Release";
      mathScaleBox.setAttribute("data-tex", "P(k) = \\frac{1 - \\alpha}{1 + \\alpha}\\, \\alpha^{|k|}, \\quad \\alpha = e^{-\\epsilon / \\Delta f}");
      mathLaplaceBox.setAttribute("data-tex", "\\tilde{y} = x_{\\text{clamped}} + k, \\quad k \\in \\mathbb{Z}");
    } else if (mech === "snapping") {
      mechanismBadgeLabel.textContent = "Snapping Mechanism Active";
      formulaParamTitle.textContent = "2. Internal Epsilon";
      formulaMechanismTitle.textContent = "3. Snapped Noisy Release";
      mathScaleBox.setAttribute("data-tex", "\\epsilon_{\\text{internal}} = \\frac{\\epsilon - 2\\eta}{1 + 12 B \\eta}");
      mathLaplaceBox.setAttribute("data-tex", "\\tilde{y} = \\text{clamp}_B\\left(\\left\\lfloor \\text{clamp}_B(x) + \\text{Lap}(1/\\epsilon_{\\text{internal}}) \\right\\rceil_{\\Lambda}\\right)");
    } else {
      mechanismBadgeLabel.textContent = "Laplace Mechanism Active";
      formulaParamTitle.textContent = "2. Mechanism Noise Scale Parameter";
      formulaMechanismTitle.textContent = "3. Mechanism Noisy Output Generation";
      mathScaleBox.setAttribute("data-tex", "b = \\frac{\\Delta f}{\\epsilon} = \\frac{|U - L|}{\\epsilon}");
      mathLaplaceBox.setAttribute("data-tex", "\\tilde{y} = x_{\\text{clamped}} + \\text{Laplace}\\left(0, b\\right)");
    }

    renderKaTeXElements();
  }

  fileUploadInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (evt) => {
        codeEditor.value = evt.target.result;
        updateLineNumbers();
        setTimeout(() => btnAnalyzeCode.click(), 200);
      };
      reader.readAsText(file);
    }
  });

  btnAnalyzeCode.addEventListener("click", async () => {
    const codeText = codeEditor.value;
    if (!codeText.trim()) return;

    btnAnalyzeCode.textContent = "Analyzing...";
    btnAnalyzeCode.disabled = true;

    try {
      const res = await apiFetch("/api/analyze_code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: codeText })
      });
      const data = await res.json();
      if (data.error) {
        showAnalysisError(data.error);
        return;
      }
      renderCodeAnalysisResults(data);
      renderPipelineForCode(data);
      applyDetectedParams(data.detected_params);
      await fetchStatus();
    } catch (err) {
      console.error("Code analysis error:", err);
      showAnalysisError("Could not reach the analysis service.");
    } finally {
      btnAnalyzeCode.textContent = "Analyze Code (Static)";
      btnAnalyzeCode.disabled = false;
    }
  });

  function showAnalysisError(message) {
    codeAnalysisResults.style.display = "block";
    resultBanner.className = "result-banner REJECTED";
    resultStatus.textContent = "ANALYSIS NOT RUN";
    resultSummaryText.textContent = message;
    staticFindingsList.innerHTML = "";
    dynamicStdoutContainer.textContent = "";
  }

  // only copy over what the linter actually resolved; leave the rest of the form alone
  function applyDetectedParams(params) {
    if (!params) return;
    selectMechanism.value = params.mechanism;
    updateFormulaCardHeaders(params.mechanism);
    const fields = { "inp-eps": params.epsilon, "inp-delta": params.delta, "inp-lower": params.lower, "inp-upper": params.upper };
    for (const [id, value] of Object.entries(fields)) {
      if (typeof value === "number") document.getElementById(id).value = value;
    }
    calcClampingSub.textContent = "Static analysis only: no query was run";
    calcScaleSub.textContent = typeof params.epsilon === "number" && typeof params.sensitivity === "number" && params.mechanism === "laplace"
      ? `From the code (line ${params.line}): b = ${params.sensitivity} / ${params.epsilon} = ${fmt(params.sensitivity / params.epsilon)}`
      : "Not determinable from the code alone";
    calcLaplaceSub.textContent = "Static analysis only: no noise was drawn";
    calcRoundingSub.textContent = ROUNDING_NOTE;
  }

  if (btnLoadValidSample) {
    btnLoadValidSample.addEventListener("click", () => {
      codeEditor.value = `import diffprivlib.mechanisms as dp_mech

# Laplace mechanism with a fixed, public sensitivity
epsilon = 1.0
sensitivity = 1.0
raw_value = 42.0

mech = dp_mech.Laplace(epsilon=epsilon, sensitivity=sensitivity)
noisy_result = mech.randomise(raw_value)
print("Differentially Private Output:", noisy_result)
`;
      updateLineNumbers();
      setTimeout(() => btnAnalyzeCode.click(), 100);
    });
  }

  if (btnLoadVulnerableSample) {
    btnLoadVulnerableSample.addEventListener("click", () => {
      codeEditor.value = `import numpy as np
import diffprivlib.mechanisms as dp_mech
import diffprivlib.tools as dp_tools

salaries = np.array([50000, 70000, 45000, 60000, 55000])

# 1: epsilon above the configured threshold, and a hardcoded seed
mech1 = dp_mech.Laplace(epsilon=15.0, sensitivity=1.0, random_state=12345)
res1 = mech1.randomise(10.0)

# 2: invalid epsilon
mech2 = dp_mech.Laplace(epsilon=0.0, sensitivity=1.0)

# 3: no clipping bounds, so the sensitivity is taken from the data
dp_mean = dp_tools.mean(salaries, epsilon=1.0)

# 4: hand-written noise with a data-dependent range
spread = np.max(salaries) - np.min(salaries)
noisy_sum = np.sum(salaries) + np.random.laplace(0, spread / 1.0)

# 5: exact statistic released next to the DP result
print("Exact mean:", np.mean(salaries), "DP mean:", dp_mean)
`;
      updateLineNumbers();
      setTimeout(() => btnAnalyzeCode.click(), 100);
    });
  }

  function readQueryForm() {
    return {
      mechanism: selectMechanism.value,
      value: parseFloat(document.getElementById("inp-val").value),
      epsilon: parseFloat(document.getElementById("inp-eps").value),
      delta: parseFloat(document.getElementById("inp-delta").value || 1e-6),
      lower: parseFloat(document.getElementById("inp-lower").value),
      upper: parseFloat(document.getElementById("inp-upper").value),
      seed: document.getElementById("inp-seed").value || null,
      dataset_size: document.getElementById("inp-n").value || null
    };
  }

  queryForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    await executeQuery(readQueryForm());
  });

  const selectBudgetEnvelope = document.getElementById("select-budget-envelope");
  if (selectBudgetEnvelope) {
    selectBudgetEnvelope.addEventListener("change", async () => {
      const totEps = parseFloat(selectBudgetEnvelope.value);
      await apiFetch("/api/set_budget", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ total_epsilon: totEps })
      });
      await fetchStatus();
      await fetchLogs();
      resetPipeline();
    });
  }

  resetBtn.addEventListener("click", async () => {
    await apiFetch("/api/reset", { method: "POST" });
    await fetchStatus();
    await fetchLogs();
    resetPipeline();
  });

  // keeps asking for a bit more than is left (never above the per-query cap) until the accountant says no
  exhaustBtn.addEventListener("click", async () => {
    exhaustBtn.disabled = true;
    try {
      const base = { ...readQueryForm(), seed: null, dataset_size: null };
      if (base.mechanism === "gaussian") base.mechanism = "laplace"; // keep the delta budget out of it
      for (let i = 0; i < 25; i++) {
        const st = await fetchStatus();
        if (!st) break;
        const epsilon = Math.min(maxQueryEpsilon, st.remaining_epsilon + 0.5);
        const result = await executeQuery({ ...base, epsilon });
        if (!result || result.status !== "SUCCESS") break;
      }
    } finally {
      exhaustBtn.disabled = false;
    }
  });

  async function executeQuery(payload) {
    try {
      const res = await apiFetch("/api/execute_query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const resultData = await res.json();
      if (resultData.error && !resultData.stages) {
        renderRequestError(resultData.error);
        return null;
      }
      renderPipeline(resultData);
      renderCalculations(resultData);
      await fetchStatus();
      await fetchLogs();
      return resultData;
    } catch (err) {
      console.error("Query execution error:", err);
      renderRequestError("Could not reach the query service.");
      return null;
    }
  }

  function renderRequestError(message) {
    pipelineContainer.innerHTML = `
      <div class="pipeline-step blocked">
        <div class="step-num">!</div>
        <div class="step-content">
          <div class="step-title">Request rejected before the pipeline ran</div>
          <div class="step-detail">${esc(message)}</div>
        </div>
      </div>`;
  }

  function renderCodeAnalysisResults(data) {
    codeAnalysisResults.style.display = "block";

    const staticRep = data.static_analysis || {};
    const verdict = staticRep.verdict || "PASSED";
    resultBanner.className = `result-banner ${esc(verdict)}`;
    resultStatus.textContent = `VERDICT: ${verdict}`;

    const findings = staticRep.findings || [];
    const calls = staticRep.dp_calls_count || 0;
    if (findings.length === 0) {
      resultSummaryText.textContent = `No rule matched (${calls} DP call(s) recognized). This is not proof that the code is private.`;
      staticFindingsList.innerHTML = `<div style="color: var(--accent-emerald); font-size: 0.85rem; font-family: var(--font-mono); font-weight:600;">No findings from the 17 implemented rules.</div>`;
    } else {
      resultSummaryText.textContent = `${findings.length} finding(s) across ${calls} recognized DP call(s).`;
      staticFindingsList.innerHTML = findings.map(f => `
        <div class="finding-item ${esc(f.severity)}">
          <div class="finding-rule">[LINE ${esc(f.line)}] [${esc(f.severity)}] ${esc(f.rule)}</div>
          <div class="finding-msg">${esc(f.message)}</div>
        </div>
      `).join("");
    }

    const lines = ["Submitted Python is analyzed statically and is never executed."];
    if (typeof staticRep.cumulative_epsilon === "number") {
      lines.push(`Summed epsilon of the releases found: ${staticRep.cumulative_epsilon} (releases inside loops are counted once).`);
    }
    if (staticRep.unresolved_releases) {
      lines.push(`${staticRep.unresolved_releases} release(s) had an epsilon that could not be resolved statically and are not in that sum.`);
    }
    const symbols = Object.entries(data.symbol_table || {});
    if (symbols.length) {
      lines.push("Resolved variables: " + symbols.map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(", "));
    }
    dynamicStdoutContainer.textContent = lines.join("\n");
  }

  function renderPipelineForCode(data) {
    const staticRep = data.static_analysis || {};
    const passed = staticRep.verdict === "PASSED" || staticRep.verdict === "WARNING";
    const blocking = (staticRep.findings || []).filter(f => f.severity === "CRITICAL" || f.severity === "HIGH");
    const detail = passed
      ? `No CRITICAL or HIGH finding. ${esc(staticRep.dp_calls_count || 0)} DP call(s) recognized.`
      : blocking.map(f => `[LINE ${esc(f.line)}] ${esc(f.message)}`).join("<br>");

    const notRun = (num, title) => `
      <div class="pipeline-step not-run">
        <div class="step-num">${num}</div>
        <div class="step-content">
          <div class="step-title" style="display:flex; justify-content:space-between; align-items:center;">
            <span>${title}</span>
            <span class="status-badge NOT_RUN">[NOT RUN]</span>
          </div>
          <div class="step-detail">Submitted code is not executed, so this runtime stage did not run.</div>
        </div>
      </div>`;

    pipelineContainer.innerHTML = `
      <div class="pipeline-step ${passed ? "passed" : "blocked"}">
        <div class="step-num">0</div>
        <div class="step-content">
          <div class="step-title" style="display:flex; justify-content:space-between; align-items:center;">
            <span>Static analysis (no execution)</span>
            <span class="status-badge ${passed ? "SUCCESS" : "BLOCKED"}">[${esc(staticRep.verdict || "PASSED")}]</span>
          </div>
          <div class="step-detail">${detail}</div>
        </div>
      </div>
      ${notRun(1, ":before advice (validation, then budget reservation)")}
      ${notRun(2, "Target mechanism")}
      ${notRun(3, ":after advice (output rounding and audit)")}
    `;
  }

  function renderKaTeXElements() {
    if (typeof katex === "undefined") return;

    document.querySelectorAll(".tex-render").forEach(el => {
      const tex = el.getAttribute("data-tex");
      if (tex) {
        try {
          el.innerHTML = "";
          katex.render(tex, el, { displayMode: false, throwOnError: false });
        } catch (e) {
          el.textContent = tex;
        }
      }
    });

    document.querySelectorAll(".tex-render-display").forEach(el => {
      const tex = el.getAttribute("data-tex");
      if (tex) {
        try {
          el.innerHTML = "";
          katex.render(tex, el, { displayMode: true, throwOnError: false });
        } catch (e) {
          el.textContent = tex;
        }
      }
    });
  }

  async function fetchStatus() {
    try {
      const res = await apiFetch("/api/status");
      const st = await res.json();
      if (typeof st.max_query_epsilon === "number") maxQueryEpsilon = st.max_query_epsilon;

      metricConsumed.textContent = (st.consumed_epsilon || 0).toFixed(3);
      metricRemaining.textContent = (st.remaining_epsilon || 0).toFixed(3);
      metricQueries.textContent = st.query_count || 0;

      const pct = Math.min(100, ((st.consumed_epsilon / st.total_epsilon) * 100)).toFixed(1);
      progressPercentLbl.textContent = `${pct}%`;
      progressBarFill.style.width = `${pct}%`;

      if (pct > 80) {
        progressBarFill.classList.add("warning");
      } else {
        progressBarFill.classList.remove("warning");
      }
      return st;
    } catch (err) {
      console.error("Error fetching status:", err);
      return null;
    }
  }

  async function fetchLogs() {
    try {
      const res = await apiFetch("/api/logs");
      const data = await res.json();
      const logs = data.logs || [];

      if (logs.length === 0) {
        logTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No query history yet. Run a query to add a temporary session entry.</td></tr>`;
        return;
      }

      // newest first
      const recentLogs = logs.slice().reverse().slice(0, 5);

      logTableBody.innerHTML = recentLogs.map(l => `
        <tr>
          <td>${esc(new Date(l.timestamp).toLocaleTimeString())}</td>
          <td><code>${esc(l.target)}</code></td>
          <td>${fmt(l.consumed_epsilon)}</td>
          <td>${esc(l.dataset_size || "N/A")}</td>
          <td><span class="status-badge ${esc(l.status)}">${esc(l.status)}</span></td>
        </tr>
      `).join("");
    } catch (err) {
      console.error("Error fetching logs:", err);
    }
  }

  function renderCalculations(resData) {
    const calc = resData.calculations;
    const input = resData.input || {};

    calcClampingSub.textContent = `Sensitivity Δf = ${fmt(input.sensitivity, 2)} | Clamped input x' = ${input.clamped_input}`;
    if (resData.status === "SUCCESS" && calc) {
      calcScaleSub.textContent = `${calc.param_name}: ${fmt(calc.param_value, 6)}`;
      calcLaplaceSub.textContent = `Drawn noise: ${calc.noise_drawn > 0 ? "+" : ""}${fmt(calc.noise_drawn)} | Release: ${fmt(resData.final_result, 6)}`;
    } else {
      calcScaleSub.textContent = `Not computed: ${resData.error || "query did not run"}`;
      calcLaplaceSub.textContent = "No noise was drawn";
    }
    calcRoundingSub.textContent = ROUNDING_NOTE;
  }

  // draws the stage trace the server recorded, so this is what actually ran
  function renderPipeline(resData) {
    const byStage = {};
    (resData.stages || []).forEach(s => { byStage[s.stage] = s; });
    const input = resData.input || {};

    const describe = {
      validate: s => `ε=${esc(s.epsilon)} (per-query cap ${esc(s.max_epsilon)}), δ=${esc(s.delta)}, n=${esc(s.dataset_size ?? "not given")}`,
      reserve: s => `Reserved ε=${esc(s.requested_epsilon)}, δ=${esc(s.requested_delta)} | Cumulative ε=${fmt(s.consumed_cumulative, 3)} of ${esc(s.total_epsilon)}`,
      target: () => `Ran ${esc(resData.target)} on the clamped input ${esc(input.clamped_input)}`,
      after: () => `Output rounded and release recorded: ${fmt(resData.final_result, 6)}`
    };
    const steps = [
      ["validate", ":before advice 1: parameter validation"],
      ["reserve", ":before advice 2: budget reservation"],
      ["target", "Target mechanism execution"],
      ["after", ":after advice: output rounding and audit"]
    ];

    pipelineContainer.innerHTML = `
      <div class="pipeline-step passed">
        <div class="step-num">0</div>
        <div class="step-content">
          <div class="step-title">Input clamping (before the pipeline)</div>
          <div class="step-detail">Input x=${esc(input.raw_input)} | Clamped x'=${esc(input.clamped_input)} | Bounds [${esc(input.bounds?.[0])}, ${esc(input.bounds?.[1])}]${input.clamped_applied ? " | value was clamped" : ""}</div>
        </div>
      </div>
      ${steps.map(([stage, title], i) => {
        const s = byStage[stage];
        const cls = !s ? "not-run" : s.status === "PASSED" ? "passed" : "blocked";
        const badge = !s ? "NOT_RUN" : s.status === "PASSED" ? "SUCCESS" : "BLOCKED";
        const label = !s ? "NOT RUN" : s.status;
        let detail = "Not reached.";
        if (s && s.status === "PASSED") detail = describe[stage](s);
        if (s && s.status !== "PASSED") detail = `<span style="color: var(--accent-rose); font-weight:600;">${esc(s.error)}</span>${s.refunded ? "<br>The reserved budget was refunded." : ""}`;
        return `
          <div class="pipeline-step ${cls}">
            <div class="step-num">${i + 1}</div>
            <div class="step-content">
              <div class="step-title" style="display:flex; justify-content:space-between; align-items:center;">
                <span>${title}</span>
                <span class="status-badge ${badge}">[${esc(label)}]</span>
              </div>
              <div class="step-detail">${detail}</div>
            </div>
          </div>`;
      }).join("")}
    `;
  }

  function resetPipeline() {
    pipelineContainer.innerHTML = `
      <div class="pipeline-step">
        <div class="step-num">1</div>
        <div class="step-content">
          <div class="step-title">:before advice 1: parameter validation</div>
          <div class="step-detail">Checks <span class="tex-render" data-tex="\\epsilon \\in (0, \\epsilon_{\\max}]"></span>, <span class="tex-render" data-tex="\\delta \\le 1/n^2"></span> when n is given, and seed reuse.</div>
        </div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">2</div>
        <div class="step-content">
          <div class="step-title">:before advice 2: budget reservation</div>
          <div class="step-detail">Reserves the query's budget from the session accountant; refunded if the mechanism fails.</div>
        </div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">3</div>
        <div class="step-content">
          <div class="step-title">Target mechanism execution</div>
          <div class="step-detail">The selected IBM diffprivlib mechanism.</div>
        </div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">4</div>
        <div class="step-content">
          <div class="step-title">:after advice: output rounding and audit</div>
          <div class="step-detail">Rounds float output and adds a temporary, browser-session history entry.</div>
        </div>
      </div>
    `;
    calcClampingSub.textContent = "Run a query to view instantiated calculation";
    calcScaleSub.textContent = "Run a query to view instantiated calculation";
    calcLaplaceSub.textContent = "Run a query to view instantiated calculation";
    calcRoundingSub.textContent = ROUNDING_NOTE;
    renderKaTeXElements();
  }
});
