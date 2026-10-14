// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

library GovProvRoles {
    bytes32 internal constant GOVERNANCE_ADMIN_ROLE = keccak256("GOVERNANCE_ADMIN_ROLE");
    bytes32 internal constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    bytes32 internal constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 internal constant POLICY_EVALUATOR_ROLE = keccak256("POLICY_EVALUATOR_ROLE");
    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 internal constant SECURITY_APPROVER_ROLE = keccak256("SECURITY_APPROVER_ROLE");
    bytes32 internal constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");
    bytes32 internal constant LEDGER_WRITER_ROLE = keccak256("LEDGER_WRITER_ROLE");
    bytes32 internal constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
}
