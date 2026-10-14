const state = {
  data: null,
  selectedRun: null,
  selectedReplay: null,
  selectedFault: null,
};

const views = [...document.querySelectorAll(".view")];
const tabs = [...document.querySelectorAll(".tab")];

tabs.forEach((tab) => {
  tab.addEventListener("click", () => showView(tab.dataset.view));
});

loadData();

async function loadData() {
  try {
    const response = await fetch("./demo-data/ui-data.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    state.data = await response.json();
    state.selectedRun = state.data.runs[0]?.run_id ?? null;
    state.selectedReplay = state.data.replays[0]?.workflow_id ?? null;
    state.selectedFault = state.data.faults[0]?.workflow_id ?? null;
    document.querySelector("#data-status").textContent = `${state.data.runs.length} run(s), ${state.data.replays.length} replay record(s), generated ${state.data.generated_at}`;
    renderAll();
  } catch (error) {
    document.querySelector("#data-status").textContent = "No generated UI data found. Run docker compose run --rm audit-ui-build from git/software.";
    views.forEach((view) => {
      view.innerHTML = `<div class="card"><h2>Data Required</h2><p>${escapeHtml(error.message)}</p></div>`;
    });
  }
}

function showView(id) {
  tabs.forEach((tab) => tab.classList.toggle("is-active", tab.dataset.view === id));
  views.forEach((view) => view.classList.toggle("is-active", view.id === id));
}

function renderAll() {
  renderRuns();
  renderMetrics();
  renderReplay();
  renderFaults();
  renderDemo();
}

function renderRuns() {
  const rows = state.data.runs.map((run) => [
    run.run_id,
    run.matrix ?? "unknown",
    run.configuration_count,
    run.scenario_count,
    run.workflow_count,
    run.fault_count,
    badge(run.overall_status === "pass" ? "pass" : "warn", run.overall_status),
  ]);
  document.querySelector("#runs").innerHTML = `
    <h2>Experiment Runs</h2>
    <div class="grid three">
      ${stat("Runs", state.data.runs.length)}
      ${stat("Replay records", state.data.replays.length)}
      ${stat("Fault inspections", state.data.faults.length)}
    </div>
    ${table(["Run", "Matrix", "Configs", "Scenarios", "Workflows", "Faults", "Status"], rows)}
  `;
}

function renderMetrics() {
  const runOptions = options(state.data.runs.map((run) => run.run_id), state.selectedRun);
  const metrics = state.data.metrics[state.selectedRun] ?? Object.values(state.data.metrics)[0];
  const rows = metrics.configurations.map((item) => [
    item.configuration,
    percent(item.precision),
    percent(item.recall),
    percent(item.f1),
    percent(item.reconstruction_completeness),
    percent(item.drift_classification_accuracy),
    `${item.median_workflow_latency_ms} ms`,
    item.transactions_per_workflow,
  ]);
  document.querySelector("#metrics").innerHTML = `
    <div class="toolbar">
      <h2>Metrics</h2>
      <select id="metrics-run">${runOptions}</select>
    </div>
    <div class="grid three">
      ${stat("Workflows", metrics.workflow_count)}
      ${stat("Configurations", metrics.configurations.length)}
      ${stat("GovReplay recall", percent(metrics.configurations.find((item) => item.configuration === "govreplay_besu")?.recall ?? 0))}
    </div>
    <div class="card"><p>${escapeHtml(metrics.bounded_claim ?? "")}</p></div>
    ${table(["Configuration", "Precision", "Recall", "F1", "Reconstruction", "Drift accuracy", "Median workflow", "Tx/workflow"], rows)}
  `;
  document.querySelector("#metrics-run").addEventListener("change", (event) => {
    state.selectedRun = event.target.value;
    renderMetrics();
  });
}

function renderReplay() {
  const replays = state.data.replays.filter((item) => item.run_id === state.selectedRun);
  if (!replays.some((item) => item.workflow_id === state.selectedReplay)) {
    state.selectedReplay = replays[0]?.workflow_id ?? null;
  }
  const replay = replays.find((item) => item.workflow_id === state.selectedReplay) ?? replays[0];
  const replayOptions = options(replays.map((item) => item.workflow_id), replay?.workflow_id);
  document.querySelector("#replay").innerHTML = replay === undefined ? empty("No replay records") : `
    <div class="toolbar">
      <h2>Audit Replay</h2>
      <select id="replay-id">${replayOptions}</select>
    </div>
    <div class="grid three">
      ${stat("Deployment", replay.deployment_id)}
      ${stat("Scenario", replay.scenario_id)}
      ${stat("Verdict", badge(replay.verdict === "PASS" ? "pass" : "fail", replay.verdict))}
    </div>
    <div class="lifecycle">
      ${replay.lifecycle.map(renderNode).join("")}
    </div>
    ${table(["Check", "Stage", "Status", "Code", "Detail"], replay.checks.map((check) => [
      check.name,
      check.stage,
      badge(check.status === "PASS" ? "pass" : check.status === "FAIL" ? "fail" : "warn", check.status),
      check.code ?? "none",
      check.detail,
    ]))}
  `;
  document.querySelector("#replay-id")?.addEventListener("change", (event) => {
    state.selectedReplay = event.target.value;
    renderReplay();
  });
}

function renderFaults() {
  const faults = state.data.faults.filter((item) => item.run_id === state.selectedRun);
  if (!faults.some((item) => item.workflow_id === state.selectedFault)) {
    state.selectedFault = faults[0]?.workflow_id ?? null;
  }
  const fault = faults.find((item) => item.workflow_id === state.selectedFault) ?? faults[0];
  const faultOptions = options(faults.map((item) => item.workflow_id), fault?.workflow_id);
  document.querySelector("#faults").innerHTML = fault === undefined ? empty("No fault records") : `
    <div class="toolbar">
      <h2>Fault Inspection</h2>
      <select id="fault-id">${faultOptions}</select>
    </div>
    <div class="grid three">
      ${stat("Fault", fault.fault_id)}
      ${stat("Scenario", fault.scenario_id)}
      ${stat("Localization", badge(fault.localization_status, fault.localization_status))}
    </div>
    ${table(["Field", "Expected", "Actual"], [
      ["Verdict", fault.expected_verdict, fault.actual_verdict],
      ["Failure stage", fault.expected_failure_stage ?? "none", fault.actual_failure_stage ?? "none"],
      ["Failure code", fault.expected_failure_code ?? "none", fault.actual_failure_code ?? "none"],
      ["Boundary", fault.injected_at_boundary ?? "not recorded", fault.system_configuration],
    ])}
    <div class="card"><h3>Replay Trace Summary</h3><p>${escapeHtml(fault.replay_trace_summary)}</p></div>
  `;
  document.querySelector("#fault-id")?.addEventListener("change", (event) => {
    state.selectedFault = event.target.value;
    renderFaults();
  });
}

function renderDemo() {
  const rows = state.data.demos.map((demo) => [
    demo.title,
    demo.scenario_id,
    demo.policy_version ?? "unknown",
    demo.fault_id ?? "none",
    demo.deployment_id,
    demo.purpose,
  ]);
  document.querySelector("#demo").innerHTML = `
    <h2>Demo Walkthroughs</h2>
    <div class="grid two">
      ${state.data.demos.map((demo) => `
        <button class="card demo-jump" data-workflow="${escapeHtml(demo.workflow_id)}">
          <h3>${escapeHtml(demo.title)}</h3>
          <p>${escapeHtml(demo.purpose)}</p>
        </button>
      `).join("")}
    </div>
    ${table(["Demo", "Scenario", "Policy", "Fault", "Deployment", "Purpose"], rows)}
  `;
  [...document.querySelectorAll(".demo-jump")].forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedReplay = button.dataset.workflow;
      showView("replay");
      renderReplay();
    });
  });
}

function renderNode(node) {
  return `
    <div class="node ${node.verification_verdict === "FAIL" ? "fail" : ""} ${node.present ? "" : "missing"}">
      <div class="node-title">${escapeHtml(node.label)}</div>
      <div class="node-line">hash: ${escapeHtml(node.hash_status)}</div>
      <div class="node-line">signature: ${escapeHtml(node.signature_status)}</div>
      <div class="node-line">ledger: ${escapeHtml(node.ledger_status)}</div>
      <div class="node-line">policy: ${escapeHtml(node.policy_status)}</div>
      ${badge(node.verification_verdict === "PASS" ? "pass" : node.verification_verdict === "FAIL" ? "fail" : "warn", node.verification_verdict)}
    </div>
  `;
}

function stat(label, value) {
  return `<div class="card stat"><span class="label">${escapeHtml(label)}</span><span class="value">${value}</span></div>`;
}

function table(headers, rows) {
  return `
    <div class="table-wrap">
      <table>
        <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
        <tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody>
      </table>
    </div>
  `;
}

function badge(kind, value) {
  return `<span class="badge ${escapeHtml(kind)}">${escapeHtml(String(value))}</span>`;
}

function options(values, selected) {
  return values.map((value) => `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(value)}</option>`).join("");
}

function percent(value) {
  return `${Math.round(value * 1000) / 10}%`;
}

function empty(message) {
  return `<div class="card"><h2>${escapeHtml(message)}</h2></div>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
