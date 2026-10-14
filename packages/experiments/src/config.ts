import { readFileSync } from "node:fs";
import { ALL_FAULT_IDS, POLICY_VERSIONS, SCENARIOS, SYSTEM_CONFIGURATIONS, type ExperimentConfig } from "./model.ts";

export function parseExperimentConfig(path: string): ExperimentConfig {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(parsed)) {
    throw new TypeError(`Experiment config must be a JSON object: ${path}`);
  }
  const config: ExperimentConfig = {
    run_id: stringField(parsed, "run_id"),
    matrix: enumField(parsed, "matrix", ["debug", "minimum_publishable", "arpe_basic_matrix", "arpe_hard_matrix"]),
    system_configurations: enumArray(parsed, "system_configurations", SYSTEM_CONFIGURATIONS),
    scenarios: enumArray(parsed, "scenarios", SCENARIOS),
    policy_versions: enumArray(parsed, "policy_versions", POLICY_VERSIONS),
    fault_ids: enumArray(parsed, "fault_ids", ALL_FAULT_IDS),
    seeds: numberArray(parsed, "seeds"),
    current_policy_version: enumField(parsed, "current_policy_version", POLICY_VERSIONS),
  };
  if (config.seeds.length === 0) {
    throw new TypeError("Experiment config must include at least one seed");
  }
  return config;
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`Expected non-empty string field ${key}`);
  }
  return value;
}

function enumField<const T extends readonly string[]>(record: Record<string, unknown>, key: string, allowed: T): T[number] {
  const value = stringField(record, key);
  if (!allowed.includes(value)) {
    throw new TypeError(`${key} must be one of ${allowed.join(", ")}`);
  }
  return value;
}

function enumArray<const T extends readonly string[]>(record: Record<string, unknown>, key: string, allowed: T): T[number][] {
  const value = record[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${key} must be a non-empty array`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw new TypeError(`${key} contains unsupported value ${String(item)}`);
    }
    return item;
  });
}

function numberArray(record: Record<string, unknown>, key: string): number[] {
  const value = record[key];
  if (!Array.isArray(value) || value.some((item) => !Number.isInteger(item) || item < 0)) {
    throw new TypeError(`${key} must be an array of non-negative integers`);
  }
  return value as number[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
