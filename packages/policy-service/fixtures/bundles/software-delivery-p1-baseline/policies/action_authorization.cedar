permit(
  principal,
  action == GovProv::Action::"propose_runbook_update",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  ["staging", "documentation"].contains(resource.environment) &&
  ["low", "medium"].contains(context.risk_tier) &&
  ["baseline", "strengthened"].contains(context.evidence_profile)
};

permit(
  principal,
  action == GovProv::Action::"propose_config_change",
  resource
)
when {
  principal has roles &&
  principal.roles.contains("AGENT_ROLE") &&
  context.approval_profile == "single_config_approver" &&
  resource.environment == "staging"
};
