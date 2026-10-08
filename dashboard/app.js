"use strict";

const API = "/api/v1/security";
const COMPONENT_LABELS = {
  security_router: "Security Router",
  input_gateway: "Input Gateway",
  threat_detector: "Threat Detector",
  risk_engine: "Risk Engine",
  policy_engine: "Policy Engine",
  data_classifier: "Data Classifier",
  tool_gateway: "Tool Gateway",
  audit_logging: "Audit Logging",
};
const CATEGORY_ORDER = [
  "benign", "prompt_injection", "data_exfiltration", "credential_theft",
  "tool_abuse", "suspicious", "not_assessed", "unknown",
];
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

const $ = (id) => document.getElementById(id);

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function setConnection(ok, message) {
  const banner = $("connection-banner");
  banner.classList.remove("pending", "connected", "failed");
  banner.classList.add(ok ? "connected" : "failed");
  $("connection-label").textContent = message;
  $("sidebar-connection").textContent = ok ? "Connected" : "Unavailable";
}

function showPageError(message) {
  const box = $("page-error");
  box.textContent = message;
  box.hidden = false;
}

function clearPageError() {
  $("page-error").hidden = true;
  $("page-error").textContent = "";
}

function renderMetric(id, value) {
  $(id).textContent = Number.isInteger(value) && value >= 0 ? String(value) : "—";
}

function sortedKeys(counts, preferredOrder) {
  const keys = Object.keys(counts || {});
  return keys.sort((a, b) => {
    const ai = preferredOrder.indexOf(a);
    const bi = preferredOrder.indexOf(b);
    if (ai >= 0 || bi >= 0) return (ai < 0 ? Infinity : ai) - (bi < 0 ? Infinity : bi);
    return a.localeCompare(b);
  });
}

function humanize(value) {
  return String(value).replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderDistribution(containerId, counts, order, total, severity = false) {
  const container = $(containerId);
  const keys = sortedKeys(counts, order);
  if (keys.length === 0) {
    container.innerHTML = '<p class="empty-copy">No data recorded yet.</p>';
    return;
  }
  container.replaceChildren();
  for (const key of keys) {
    const count = Number(counts[key]);
    const ratio = Number.isFinite(count) && count > 0 && total > 0 ? Math.min(100, (count / total) * 100) : 0;
    const row = document.createElement("div");
    row.className = `distribution-row${severity ? " severity-row" : ""}`;
    const name = document.createElement("span");
    name.className = "distribution-name";
    name.textContent = humanize(key);
    const track = document.createElement("span");
    track.className = "bar-track";
    track.setAttribute("aria-label", `${humanize(key)} ${count} events`);
    const fill = document.createElement("span");
    fill.className = "bar-fill";
    fill.style.width = `${ratio}%`;
    track.append(fill);
    const value = document.createElement("span");
    value.className = "distribution-count";
    value.textContent = Number.isInteger(count) ? String(count) : "—";
    row.append(name, track, value);
    container.append(row);
  }
}

function renderSummary(summary) {
  renderMetric("metric-total", summary.total_events);
  renderMetric("metric-allowed", summary.allowed_events);
  renderMetric("metric-blocked", summary.blocked_events);
  renderMetric("metric-review", summary.review_events);
  const total = Number.isInteger(summary.total_events) ? summary.total_events : 0;
  renderDistribution("category-list", summary.threat_categories, CATEGORY_ORDER, total);
  renderDistribution("severity-list", summary.severities, SEVERITY_ORDER, total, true);
}

function badge(action) {
  const normalized = ["ALLOW", "REVIEW", "BLOCK"].includes(action) ? action : "REVIEW";
  const span = document.createElement("span");
  span.className = `decision-badge decision-${normalized.toLowerCase()}`;
  span.textContent = normalized;
  return span;
}

function severityClass(severity) {
  const normalized = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].includes(severity) ? severity : "UNKNOWN";
  return `severity-${normalized.toLowerCase()}`;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function renderEvents(events) {
  const rows = $("event-rows");
  rows.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "table-empty";
    cell.colSpan = 6;
    cell.textContent = "No security events recorded yet.";
    row.append(cell);
    rows.append(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const decisionCell = document.createElement("td");
    decisionCell.append(badge(event.recommended_action));
    const typeCell = document.createElement("td");
    const eventType = document.createElement("span");
    eventType.className = "event-kind";
    eventType.textContent = humanize(event.event_type || "event");
    const source = document.createElement("span");
    source.className = "event-source";
    source.textContent = event.source_type ? `Source: ${humanize(event.source_type)}` : "Source: —";
    typeCell.append(eventType, source);
    const category = document.createElement("td");
    category.textContent = humanize(event.threat_category || "unknown");
    const severity = document.createElement("td");
    const severityBadge = document.createElement("span");
    severityBadge.className = `severity-badge ${severityClass(event.severity)}`;
    severityBadge.textContent = event.severity || "UNKNOWN";
    severity.append(severityBadge);
    const score = document.createElement("td");
    score.className = "mono-value";
    score.textContent = Number.isInteger(event.risk_score) ? String(event.risk_score) : "—";
    const time = document.createElement("td");
    time.className = "mono-value";
    time.textContent = formatDate(event.timestamp);
    row.append(decisionCell, typeCell, category, severity, score, time);
    rows.append(row);
  }
  $("event-cap").textContent = `${events.length} latest ${events.length === 1 ? "event" : "events"}`;
}

function renderStatus(status) {
  const container = $("component-status");
  const entries = Object.entries(status || {});
  container.replaceChildren();
  if (entries.length === 0) {
    container.innerHTML = '<p class="empty-copy">No component status was returned.</p>';
    $("status-summary").textContent = "Status unavailable";
    return;
  }
  let active = 0;
  let unavailable = 0;
  for (const [key, state] of entries) {
    if (state === "active") active += 1;
    if (state === "not_implemented") unavailable += 1;
    const item = document.createElement("div");
    item.className = "component-item";
    const name = document.createElement("span");
    name.className = "component-name";
    name.textContent = COMPONENT_LABELS[key] || humanize(key);
    const value = document.createElement("span");
    value.className = `component-state${state === "active" ? "" : state === "not_implemented" ? " inactive" : " unknown"}`;
    value.textContent = humanize(state || "unknown");
    item.append(name, value);
    container.append(item);
  }
  $("status-summary").textContent = `${active} active · ${unavailable} not implemented`;
}

async function loadDashboard() {
  clearPageError();
  const outcomes = await Promise.allSettled([
    getJson(`${API}/monitoring/summary`),
    getJson(`${API}/monitoring?limit=12`),
    getJson(`${API}/status`),
  ]);
  const [summary, events, status] = outcomes;
  const failed = [];
  if (summary.status === "fulfilled") renderSummary(summary.value);
  else failed.push("summary");
  if (events.status === "fulfilled") renderEvents(events.value);
  else failed.push("events");
  if (status.status === "fulfilled") renderStatus(status.value);
  else failed.push("status");
  if (failed.length === outcomes.length) {
    setConnection(false, "Security API unavailable");
    showPageError("Could not connect to the AgentShield API. Check that the backend is running, then refresh.");
  } else {
    setConnection(true, failed.length ? "Connected · partial data" : "Connected to AgentShield");
    if (failed.length) showPageError(`Some dashboard data could not be loaded (${failed.join(", ")}). Refresh to try again.`);
  }
}

function resultCell(label, value, className = "") {
  const cell = document.createElement("div");
  cell.className = "result-cell";
  const title = document.createElement("small");
  title.textContent = label;
  const content = document.createElement("strong");
  content.className = className;
  content.textContent = value == null || value === "" ? "—" : String(value);
  cell.append(title, content);
  return cell;
}

function renderAnalysis(result) {
  const panel = $("analysis-result");
  panel.replaceChildren();
  const detection = result.detection_result || {};
  const heading = document.createElement("div");
  heading.className = "result-heading";
  const title = document.createElement("strong");
  title.textContent = "Backend security decision";
  heading.append(title, badge(result.action));
  const grid = document.createElement("div");
  grid.className = "result-grid";
  grid.append(
    resultCell("Risk score", Number.isInteger(result.risk_score) ? `${result.risk_score} / 100` : "—"),
    resultCell("Pipeline severity", result.severity),
    resultCell("Detector category", detection.category || result.threat),
    resultCell("Detector severity", detection.severity),
    resultCell("Detector action", detection.recommended_action),
  );
  panel.append(heading, grid);
  panel.hidden = false;
}

async function submitAnalysis(event) {
  event.preventDefault();
  const content = $("test-content").value;
  const sourceType = $("source-type").value;
  const errorBox = $("analyze-error");
  const resultPanel = $("analysis-result");
  const button = $("analyze-button");
  errorBox.hidden = true;
  errorBox.textContent = "";
  resultPanel.hidden = true;
  if (!content.trim()) {
    errorBox.textContent = "Enter a non-empty test request.";
    errorBox.hidden = false;
    return;
  }
  button.disabled = true;
  button.querySelector("span").textContent = "Analyzing…";
  try {
    const response = await fetch(`${API}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        source_type: sourceType,
        source_name: "dashboard-test-request",
        content,
        metadata: {},
      }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderAnalysis(await response.json());
    await loadDashboard();
  } catch (error) {
    const status = error.message.startsWith("HTTP ") ? ` (${error.message})` : "";
    errorBox.textContent = `The analysis request could not be completed${status}. Check the API connection and try again.`;
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Analyze request";
  }
}

$("analyze-form").addEventListener("submit", submitAnalysis);
$("refresh-button").addEventListener("click", loadDashboard);
loadDashboard();
window.setInterval(loadDashboard, 15000);
