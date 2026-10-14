import { FAULT_TRUTH, HARD_FAULT_BY_ID, governanceDomainMetadataForFault, replayIdFor, type ExperimentConfig, type GroundTruthRecord, type HardFaultId, type ScenarioId, type WorkloadInstance } from "./model.ts";
import { defaultArpeTaxonomy, metadataForFault, type ArpeTaxonomy } from "./taxonomy.ts";

export function generateWorkload(config: ExperimentConfig): WorkloadInstance[] {
  const instances: WorkloadInstance[] = [];
  for (const systemConfiguration of config.system_configurations) {
    for (const scenarioId of config.scenarios) {
      for (const policyVersion of config.policy_versions) {
        for (const faultId of config.fault_ids) {
          if (!faultAppliesToScenario(faultId, scenarioId)) {
            continue;
          }
          for (const seed of config.seeds) {
            const suffix = `${shortScenario(scenarioId)}-${policyVersion.replace("policy:", "P")}-${faultId}-${seed.toString().padStart(4, "0")}`;
            instances.push({
              run_id: config.run_id,
              workflow_id: `wf-${suffix}`,
              scenario_id: scenarioId,
              policy_version: policyVersion,
              system_configuration: systemConfiguration,
              fault_id: faultId,
              ...governanceDomainMetadataForFault(faultId),
              seed,
              agent_id: seed % 2 === 0 ? "agent:configbot" : "agent:deliverybot",
              artifact_id: `artifact-${suffix}`,
              deployment_id: `deployment-${suffix}`,
            });
          }
        }
      }
    }
  }
  return instances;
}

function faultAppliesToScenario(faultId: string, scenarioId: string): boolean {
  if (!faultId.startsWith("H")) {
    return true;
  }
  const catalog = HARD_FAULT_BY_ID.get(faultId as HardFaultId);
  return catalog?.applicable_scenarios.includes(scenarioId as ScenarioId) ?? false;
}

export function groundTruthFor(instance: WorkloadInstance, currentPolicyVersion: string, taxonomy: ArpeTaxonomy = defaultArpeTaxonomy()): GroundTruthRecord {
  const fault = FAULT_TRUTH[instance.fault_id];
  const taxonomyMetadata = metadataForFault(instance.fault_id, taxonomy);
  const expectedVerdict = instance.fault_id === "F0" ? "pass" : "fail";
  const currentCompliance = instance.policy_version === currentPolicyVersion && expectedVerdict === "pass"
    ? "pass"
    : instance.policy_version !== currentPolicyVersion && expectedVerdict === "pass"
      ? "fail"
      : "fail";
  return {
    ...instance,
    replay_id: replayIdFor(instance),
    ...taxonomyMetadata,
    expected_verdict: expectedVerdict,
    expected_failure_stage: fault.stage,
    expected_failure_code: fault.code,
    expected_historical_compliance: expectedVerdict,
    expected_current_compliance: currentCompliance,
    expected_policy_drift_class: `${expectedVerdict}_current_${currentCompliance}`,
  };
}

function shortScenario(scenarioId: string): string {
  return scenarioId.split("_")[0] ?? scenarioId;
}
