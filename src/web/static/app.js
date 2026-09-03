"use strict";

const form = document.querySelector("#analysis-form");
const fileInput = document.querySelector("#config-file");
const configText = document.querySelector("#config-text");
const vendorSelect = document.querySelector("#vendor");
const analyzeButton = document.querySelector("#analyze-button");
const statusMessage = document.querySelector("#status");
const results = document.querySelector("#results");
const modeButtons = document.querySelectorAll("[data-mode]");
const fileMode = document.querySelector("#file-mode");
const pasteMode = document.querySelector("#paste-mode");
let activeMode = "file";

const vendorLabels = {
  cisco_ios: "Cisco IOS / IOS-XE",
  aruba_aos_cx: "Aruba AOS-CX",
  aruba_aos_s: "ArubaOS-Switch (AOS-S / 2930F)",
};

for (const button of modeButtons) {
  button.addEventListener("click", () => setInputMode(button.dataset.mode));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (activeMode === "file" && !fileInput.files.length) {
    showStatus("Choose a configuration file before analyzing.", true);
    fileInput.focus();
    return;
  }
  if (activeMode === "paste" && !configText.value.trim()) {
    showStatus("Paste a configuration before analyzing.", true);
    configText.focus();
    return;
  }

  setLoading(true);
  showStatus("Analyzing configuration…");
  results.hidden = true;

  try {
    const response = await submitAnalysis();
    const payload = await response.json().catch(() => null);

    if (!response.ok) {
      throw new Error(apiErrorMessage(response.status, payload));
    }

    renderAnalysis(payload);
    showStatus("Analysis complete.");
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : "The analysis request failed. Please try again.";
    showStatus(message, true);
  } finally {
    setLoading(false);
  }
});

function setInputMode(mode) {
  activeMode = mode;
  const isFileMode = mode === "file";
  fileMode.hidden = !isFileMode;
  pasteMode.hidden = isFileMode;
  fileInput.required = isFileMode;
  configText.required = !isFileMode;
  showStatus("");

  for (const button of modeButtons) {
    const isActive = button.dataset.mode === mode;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  }
}

function submitAnalysis() {
  if (activeMode === "paste") {
    return fetch("/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        vendor: vendorSelect.value,
        config: configText.value,
      }),
    });
  }

  const formData = new FormData();
  formData.append("vendor", vendorSelect.value);
  formData.append("file", fileInput.files[0]);
  return fetch("/analyze/file", {
    method: "POST",
    body: formData,
  });
}

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading ? "Analyzing…" : "Analyze";
}

function showStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle("error", isError);
}

function apiErrorMessage(status, payload) {
  if (payload && typeof payload.detail === "string") {
    return payload.detail;
  }
  if (status === 413) {
    return "The configuration exceeds the 1 MiB upload limit.";
  }
  if (status >= 500) {
    return "The server could not complete the analysis. Please try again.";
  }
  return "The configuration could not be analyzed. Check the file and vendor.";
}

function renderAnalysis(payload) {
  const device = payload.device;
  const analysis = payload.analysis;
  const posture = payload.posture;
  const findings = payload.findings;

  renderDefinitionList(document.querySelector("#device-summary"), [
    ["Vendor", vendorLabels[device.vendor] || device.vendor],
    ["Hostname", device.hostname || "Not identified"],
  ]);

  document.querySelector("#score").textContent = posture.score === null
    ? "N/A"
    : String(posture.score);
  document.querySelector("#risk").textContent = posture.risk_level
    ? `${posture.risk_level} risk`
    : "Risk level unavailable";

  renderDefinitionList(document.querySelector("#analysis-summary"), [
    ["Parser coverage", formatPercent(analysis.parser_coverage)],
    ["Analysis confidence", titleCase(analysis.analysis_confidence)],
    [
      "Rules assessed",
      `${analysis.assessed_rule_count} of ${analysis.total_rule_count}`,
    ],
    ["Assessment ratio", formatPercent(analysis.rule_assessment_ratio)],
  ]);

  document.querySelector("#result-summary").textContent = device.hostname
    ? `Results for ${device.hostname}`
    : "Results for analyzed configuration";
  document.querySelector("#finding-count").textContent =
    `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`;

  renderFindings(findings);
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderDefinitionList(container, entries) {
  container.replaceChildren();
  for (const [label, value] of entries) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    container.append(term, description);
  }
}

function renderFindings(findings) {
  const container = document.querySelector("#findings");
  container.replaceChildren();

  if (!findings.length) {
    const emptyState = document.createElement("div");
    emptyState.className = "empty-state";
    emptyState.textContent = "No findings were reported within the assessed scope.";
    container.append(emptyState);
    return;
  }

  for (const finding of findings) {
    container.append(createFinding(finding));
  }
}

function createFinding(finding) {
  const article = element("article", "finding");
  const header = element("div", "finding-header");
  const headingGroup = document.createElement("div");
  const ruleId = element("span", "rule-id", finding.rule_id);
  const title = element("h3", "finding-title", finding.title);
  headingGroup.append(ruleId, title);

  const badges = element("div", "badges");
  badges.append(
    element(
      "span",
      `badge severity-${finding.severity}`,
      `${titleCase(finding.severity)} severity`,
    ),
    element(
      "span",
      "badge confidence",
      `${titleCase(finding.confidence)} confidence`,
    ),
  );
  header.append(headingGroup, badges);

  const body = element("div", "finding-body");
  body.append(
    detailBlock("Technical impact", finding.technical_impact),
    detailBlock("Remediation", finding.remediation),
    detailBlock(
      "Affected interfaces",
      finding.affected_interfaces.length
        ? finding.affected_interfaces.join(", ")
        : "None specified",
    ),
    evidenceBlock(finding.evidence),
    codeBlock("Safe configuration example", finding.safe_config_example),
  );
  article.append(header, body);
  return article;
}

function detailBlock(heading, content) {
  const block = element("section", "detail-block");
  block.append(element("h4", "", heading), element("p", "", content));
  return block;
}

function evidenceBlock(evidence) {
  const block = element("section", "detail-block");
  block.append(element("h4", "", "Evidence"));
  const list = element("ul", "evidence-list");
  for (const item of evidence) {
    const entry = document.createElement("li");
    entry.append(
      document.createTextNode(`Line ${item.line_number}: `),
      element("code", "", item.text),
    );
    list.append(entry);
  }
  if (!evidence.length) {
    list.append(element("li", "", "No source evidence supplied."));
  }
  block.append(list);
  return block;
}

function codeBlock(heading, content) {
  const block = element("section", "detail-block detail-wide");
  const pre = document.createElement("pre");
  pre.append(element("code", "", content));
  block.append(element("h4", "", heading), pre);
  return block;
}

function element(tagName, className = "", text = "") {
  const node = document.createElement(tagName);
  if (className) {
    node.className = className;
  }
  node.textContent = text;
  return node;
}

function formatPercent(value) {
  return value === null ? "N/A" : `${Math.round(value * 100)}%`;
}

function titleCase(value) {
  return value
    ? value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
    : "N/A";
}
