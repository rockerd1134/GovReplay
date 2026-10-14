permit(
  principal,
  action == GovProv::Action::"propose_runbook_update",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  ["documentation", "staging"].contains(resource.environment) &&
  context.evidence_profile == "strengthened" &&
  context.policy_ref_profile == "bundle_hash_present"
};

permit(
  principal,
  action == GovProv::Action::"deploy_artifact",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  resource.environment == "production" &&
  context.artifact_linkage == "approved_artifact_with_ledger_anchor" &&
  context.policy_ref_profile == "bundle_hash_present"
};

permit(
  principal,
  action == GovProv::Action::"propose_patch",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  ["staging", "production"].contains(resource.environment) &&
  context.evidence_profile == "issue_and_tests" &&
  context.artifact_linkage == "patch_artifact_reference" &&
  context.policy_ref_profile == "bundle_hash_present"
};

permit(
  principal,
  action == GovProv::Action::"request_governance_state_change",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("GOVERNANCE_ADMIN") &&
  resource.environment == "governance" &&
  context.evidence_profile == "governance_change_request" &&
  context.policy_ref_profile == "bundle_hash_present"
};
