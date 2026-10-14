import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { argv, env } from "node:process";
import { canonicalJson } from "../../attestations/src/canonical-json.ts";
import { runS1LocalHappyPath, runS1LocalScenario } from "./s1-local-runner.ts";
import { runS2LocalScenario } from "./s2-local-runner.ts";
import { runS3LocalScenario } from "./s3-local-runner.ts";
import { runS4LocalHappyPath } from "./s4-local-runner.ts";

type UiFixtureBundle = {
  schema_version: "govprov.scenario_ui_fixture_bundle.v1";
  generated_at: string;
  boundary: string;
  scenarios: UiScenarioFixture[];
};

type UiScenarioFixture = {
  scenario_id: string;
  scenario_name: string;
  workflow_id: string;
  policy_version: string;
  fault_id: string;
  expected_verdict: "pass" | "fail";
  failure_stage: string | null;
  failure_code: string | null;
  lifecycle: string[];
  actor_ids: string[];
  evidence_paths: string[];
  approval_summary: {
    approver_actor_id: string | null;
    approver_role: string | null;
    separation_of_duties: string | null;
  };
  artifact_summary: {
    artifact_id: string | null;
    artifact_type: string | null;
    artifact_digest: string | null;
    deployed_digest: string | null;
    digest_match: boolean | null;
  };
  replay_start: {
    kind: string;
    value: string;
  };
  files: Record<string, string>;
};

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultOutputRoot = join(packageRoot, "artifacts", "scenario-ui-fixtures");
const defaultRunRoot = join(packageRoot, ".tmp", "ui-fixture-runs");

export async function generateScenarioUiFixtures(options: {
  outputRoot?: string;
  runRoot?: string;
} = {}): Promise<{ bundle: UiFixtureBundle; outputPath: string }> {
  const outputRoot = options.outputRoot ?? defaultOutputRoot;
  const runRoot = options.runRoot ?? defaultRunRoot;
  mkdirSync(outputRoot, { recursive: true });

  const runs = [
    await runS1LocalHappyPath({
      outputRoot: join(runRoot, "wf-S1-P1-F0-0001"),
    }),
    await runS1LocalScenario({
      manifestPath: join(packageRoot, "examples", "scenarios", "S1_runbook_update", "faults", "F10_artifact_substitution.manifest.json"),
      outputRoot: join(runRoot, "wf-S1-P1-F10-0001"),
    }),
    await runS2LocalScenario({
      outputRoot: join(runRoot, "wf-S2-P2-F0-0001"),
    }),
    await runS2LocalScenario({
      manifestPath: join(packageRoot, "examples", "scenarios", "S2_configuration_change", "faults", "F8_separation_of_duties.manifest.json"),
      outputRoot: join(runRoot, "wf-S2-P2-F8-0001"),
    }),
    await runS3LocalScenario({
      outputRoot: join(runRoot, "wf-S3-P3-F0-0001"),
    }),
    await runS3LocalScenario({
      manifestPath: join(packageRoot, "examples", "scenarios", "S3_patch_proposal", "faults", "F10_artifact_substitution.manifest.json"),
      outputRoot: join(runRoot, "wf-S3-P3-F10-0001"),
    }),
    await runS4LocalHappyPath({
      outputRoot: join(runRoot, "wf-S4-P3-F0-0001"),
    }),
  ];

  const bundle: UiFixtureBundle = {
    schema_version: "govprov.scenario_ui_fixture_bundle.v1",
    generated_at: "2026-06-21T03:00:00Z",
    boundary: "Phase 5 UI-readable fixture only. Phase 8 owns the actual UI and Phase 6 owns full audit replay reports.",
    scenarios: runs.map((run) => summarizeRun(run.outputRoot, run.files)),
  };

  const outputPath = join(outputRoot, "scenario-runs.json");
  writeFileSync(outputPath, `${canonicalJson(bundle)}\n`);
  return { bundle, outputPath };
}

function summarizeRun(outputRoot: string, files: Record<string, string>): UiScenarioFixture {
  const runManifest = readJson(files.run_manifest);
  const evidenceBundle = readJson(files.evidence_bundle);
  const approval = readJson(files.approval);
  const artifact = readJson(files.artifact);
  const deployment = readJson(files.deployment);
  const replayFixture = readJson(files.local_replay_fixture);
  const faultReport = "local_fault_replay" in files ? readJson(files.local_fault_replay) : null;
  const baseline = readFileSync(files.baseline_logs, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const expectedFault = isRecord(replayFixture.expected_fault) ? replayFixture.expected_fault : {};
  const start = isRecord(replayFixture.start) ? replayFixture.start : {};

  return {
    scenario_id: stringField(runManifest.scenario_id),
    scenario_name: scenarioDisplayName(stringField(runManifest.scenario_id)),
    workflow_id: stringField(runManifest.workflow_id),
    policy_version: stringField(runManifest.source_manifest_mode) === "signed_offchain"
      ? stringField(readJson(files.policy_decision).policy_version)
      : stringField(readJson(files.policy_decision).policy_version),
    fault_id: stringField(runManifest.fault_id),
    expected_verdict: stringField(runManifest.expected_verdict) as "pass" | "fail",
    failure_stage: nullableString(faultReport?.failure_stage ?? expectedFault.expected_failure_stage),
    failure_code: nullableString(faultReport?.failure_code ?? expectedFault.expected_failure_code),
    lifecycle: baseline.map((event) => stringField(event.stage)),
    actor_ids: unique([
      ...baseline.map((event) => isRecord(event.payload) ? event.payload.actor_id : null),
      approval.approver_actor_id,
    ].filter((value): value is string => typeof value === "string")),
    evidence_paths: Array.isArray(evidenceBundle.evidence)
      ? evidenceBundle.evidence.map((item) => isRecord(item) ? stringField(item.path) : "")
      : [],
    approval_summary: {
      approver_actor_id: nullableString(approval.approver_actor_id),
      approver_role: nullableString(approval.approver_role),
      separation_of_duties: nullableString(approval.separation_of_duties),
    },
    artifact_summary: {
      artifact_id: nullableString(artifact.artifact_id),
      artifact_type: nullableString(artifact.artifact_type),
      artifact_digest: digestValue(artifact.content_digest),
      deployed_digest: digestValue(deployment.deployed_artifact_digest),
      digest_match: digestValue(deployment.approved_artifact_digest) === null || digestValue(deployment.deployed_artifact_digest) === null
        ? null
        : digestValue(deployment.approved_artifact_digest) === digestValue(deployment.deployed_artifact_digest),
    },
    replay_start: {
      kind: stringField(start.kind),
      value: stringField(start.value),
    },
    files: Object.fromEntries(Object.entries(files).map(([name, path]) => [name, relative(outputRoot, path).replaceAll("\\", "/")])),
  };
}

function scenarioDisplayName(scenarioId: string): string {
  return scenarioId.replace(/^S[0-9]+_/, "").replaceAll("_", " ");
}

function readJson(path: string): Record<string, unknown> {
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(value)) {
    throw new TypeError(`Expected object JSON: ${path}`);
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError(`Expected string field, got ${typeof value}`);
  }
  return value;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function digestValue(value: unknown): string | null {
  return isRecord(value) && typeof value.value === "string" ? value.value : null;
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

if (argv[1]?.endsWith("ui-fixtures.ts")) {
  const result = await generateScenarioUiFixtures({
    outputRoot: env.GOVPROV_SCENARIO_UI_FIXTURE_OUTPUT,
  });
  console.log(JSON.stringify({
    output_path: result.outputPath,
    scenario_count: result.bundle.scenarios.length,
  }, null, 2));
}
