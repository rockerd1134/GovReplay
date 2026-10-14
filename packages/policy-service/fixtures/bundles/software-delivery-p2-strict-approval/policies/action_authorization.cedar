permit(
  principal,
  action == GovProv::Action::"propose_config_change",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  resource.environment == "production" &&
  context.risk_tier == "high" &&
  context.approval_profile == "dual_distinct_config_approvers"
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
  context.approval_profile == "deploy_approver_distinct" &&
  context.artifact_linkage == "approved_artifact"
};
