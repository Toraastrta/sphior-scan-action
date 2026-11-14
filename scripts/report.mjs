// Post-processes the SARIF written by @sphior/scan for GitHub.
//
// 1. Paths: the scanner writes locations relative to the scanned directory. GitHub code
//    scanning resolves them against the repository root, so when the action scans a
//    sub-directory every location is prefixed with that directory.
// 2. Counts by severity, from each rule's `security-severity` (9.5 / 8.0 / 5.5 / 3.0 / 1.0).
// 3. A job summary with the counts and the first findings, and the step outputs.
import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { relative, sep } from "node:path";

const env = process.env;
const sarifPath = env.SPHIOR_SARIF_ABS;
const sarif = JSON.parse(readFileSync(sarifPath, "utf8"));

// ── 1. Rewrite relative locations to repository-root paths ──────────────────
const prefix = relative(env.SPHIOR_WORKSPACE, env.SPHIOR_SCAN_DIR).split(sep).join("/");
const isRelative = (uri) => typeof uri === "string" && !/^[a-z][a-z0-9+.-]*:/i.test(uri) && !uri.startsWith("/");

function rewrite(node) {
  if (Array.isArray(node)) return node.forEach(rewrite);
  if (!node || typeof node !== "object") return;
  const loc = node.artifactLocation;
  if (prefix && loc && isRelative(loc.uri) && !loc.uriBaseId) loc.uri = `${prefix}/${loc.uri}`;
  for (const value of Object.values(node)) rewrite(value);
}
if (prefix) {
  for (const run of sarif.runs ?? []) rewrite(run.results ?? []);
  writeFileSync(sarifPath, JSON.stringify(sarif));
}

// ── 2. Count by severity ────────────────────────────────────────────────────
const bucket = (score) => (score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score >= 2 ? "low" : "info");
const order = ["critical", "high", "medium", "low", "info"];
const counts = Object.fromEntries(order.map((k) => [k, 0]));
const rows = [];

for (const run of sarif.runs ?? []) {
  const rules = new Map((run.tool?.driver?.rules ?? []).map((r) => [r.id, r]));
  for (const result of run.results ?? []) {
    const rule = rules.get(result.ruleId);
    const severity = bucket(Number(rule?.properties?.["security-severity"] ?? 0));
    counts[severity] += 1;
    const physical = result.locations?.[0]?.physicalLocation;
    rows.push({
      severity,
      title: rule?.shortDescription?.text ?? result.ruleId ?? "",
      cwe: result.properties?.cwe ?? "",
      where: physical ? `${physical.artifactLocation?.uri ?? ""}:${physical.region?.startLine ?? ""}` : "",
    });
  }
}
rows.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
const total = rows.length;

// ── 3. Job summary and outputs ──────────────────────────────────────────────
const failOn = env.SPHIOR_FAIL_ON_NORM;
const failed = env.SPHIOR_EXIT === "1";
const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
const verdict = failOn === "none"
  ? "No threshold set. The job does not fail on findings."
  : failed
    ? `Findings at or above **${failOn}** were found. The job fails.`
    : `Nothing at or above **${failOn}**.`;

const lines = [
  "### SPHIOR CODE",
  "",
  verdict,
  "",
  "| Critical | High | Medium | Low | Info |",
  "|---:|---:|---:|---:|---:|",
  `| ${order.map((k) => counts[k]).join(" | ")} |`,
  "",
];
if (total > 0) {
  const shown = rows.slice(0, 30);
  lines.push("| Severity | Finding | CWE | Location |", "|---|---|---|---|");
  for (const r of shown) lines.push(`| ${r.severity} | ${cell(r.title)} | ${cell(r.cwe)} | \`${cell(r.where)}\` |`);
  if (total > shown.length) lines.push("", `${total - shown.length} more in the SARIF report.`);
  lines.push("");
}

if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n");
if (env.GITHUB_OUTPUT) {
  appendFileSync(env.GITHUB_OUTPUT, [
    `findings=${total}`,
    `critical=${counts.critical}`,
    `high=${counts.high}`,
    `medium=${counts.medium}`,
    `low=${counts.low + counts.info}`,
  ].join("\n") + "\n");
}
