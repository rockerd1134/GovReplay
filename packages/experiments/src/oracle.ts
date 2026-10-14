import { groundTruthFor } from "./workload.ts";
import type { ExperimentConfig, GroundTruthRecord, WorkloadInstance } from "./model.ts";
import type { ArpeTaxonomy } from "./taxonomy.ts";

export type OracleRecord = GroundTruthRecord;

export function buildOracleRecords(
  workload: WorkloadInstance[],
  currentPolicyVersion: ExperimentConfig["current_policy_version"],
  taxonomy: ArpeTaxonomy,
): OracleRecord[] {
  return workload.map((instance) => groundTruthFor(instance, currentPolicyVersion, taxonomy));
}
