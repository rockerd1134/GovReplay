// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

library GovProvErrors {
    error ZeroAddress();
    error ZeroHash(string field);
    error ActorNotRegistered(address actor);
    error ActorNotActive(address actor);
    error ActorAlreadyRegistered(address actor);
    error ActorAlreadyRevoked(address actor);
    error MissingRole(address actor, bytes32 role);
    error PolicyAlreadyRegistered(bytes32 policyHash);
    error PolicyNotFound(bytes32 policyHash);
    error PolicyNotActive(bytes32 policyHash);
    error PolicyRevoked(bytes32 policyHash);
    error NoActivePolicy(bytes32 scopeHash);
    error AttestationAlreadyAnchored(bytes32 attestationHash);
    error AttestationNotFound(bytes32 attestationHash);
    error ApprovalAlreadyRecorded(bytes32 approvalHash);
    error ApprovalNotFound(bytes32 approvalHash);
    error ApprovalNotValid(bytes32 approvalHash);
    error SeparationOfDutiesViolation(address proposer, address approver);
    error DeploymentAlreadyRecorded(bytes32 deploymentIdHash);
    error DeploymentNotFound(bytes32 deploymentIdHash);
    error ArtifactApprovalMissing(bytes32 actionHash, bytes32 artifactHash);
    error ContractAlreadyRegistered(bytes32 nameHash, address contractAddress);
    error ContractNotFound(bytes32 nameHash, address contractAddress);
    error ArrayLengthMismatch();
    error InvalidStatusTransition();
}
