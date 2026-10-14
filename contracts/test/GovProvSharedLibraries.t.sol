// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";
import { GovProvValidation } from "../src/lib/GovProvValidation.sol";

contract GovProvValidationHarness {
    function requireNonZeroAddress(address value) external pure {
        GovProvValidation.requireNonZeroAddress(value);
    }

    function requireNonZeroHash(bytes32 value, string memory field) external pure {
        GovProvValidation.requireNonZeroHash(value, field);
    }
}

contract GovProvSharedLibrariesTest is Test {
    GovProvValidationHarness private validation;

    function setUp() public {
        validation = new GovProvValidationHarness();
    }

    function testRoleConstantsUseStableNames() public pure {
        assertEq(GovProvRoles.GOVERNANCE_ADMIN_ROLE, keccak256("GOVERNANCE_ADMIN_ROLE"));
        assertEq(GovProvRoles.POLICY_ADMIN_ROLE, keccak256("POLICY_ADMIN_ROLE"));
        assertEq(GovProvRoles.AGENT_ROLE, keccak256("AGENT_ROLE"));
        assertEq(GovProvRoles.POLICY_EVALUATOR_ROLE, keccak256("POLICY_EVALUATOR_ROLE"));
        assertEq(GovProvRoles.APPROVER_ROLE, keccak256("APPROVER_ROLE"));
        assertEq(GovProvRoles.SECURITY_APPROVER_ROLE, keccak256("SECURITY_APPROVER_ROLE"));
        assertEq(GovProvRoles.DEPLOYER_ROLE, keccak256("DEPLOYER_ROLE"));
        assertEq(GovProvRoles.LEDGER_WRITER_ROLE, keccak256("LEDGER_WRITER_ROLE"));
        assertEq(GovProvRoles.AUDITOR_ROLE, keccak256("AUDITOR_ROLE"));
    }

    function testEnumsReserveIndexZeroForUnknownState() public pure {
        assertEq(uint8(GovProvTypes.ActorType.UNKNOWN), 0);
        assertEq(uint8(GovProvTypes.ActorStatus.UNKNOWN), 0);
        assertEq(uint8(GovProvTypes.PolicyStatus.UNKNOWN), 0);
        assertEq(uint8(GovProvTypes.ApprovalStatus.UNKNOWN), 0);
        assertEq(uint8(GovProvTypes.DeploymentStatus.UNKNOWN), 0);
        assertEq(uint8(GovProvTypes.ContractStatus.UNKNOWN), 0);
    }

    function testStructConstructionUsesBytes32Identifiers() public pure {
        GovProvTypes.ActorRecord memory actor = GovProvTypes.ActorRecord({
            actor: address(0xA11CE),
            actorIdHash: keccak256("actor:agent-alpha"),
            metadataHash: keccak256("metadata:actor:agent-alpha"),
            actorType: GovProvTypes.ActorType.AGENT,
            status: GovProvTypes.ActorStatus.ACTIVE,
            registeredAt: 10,
            suspendedAt: 0,
            revokedAt: 0,
            revocationReasonHash: bytes32(0)
        });

        GovProvTypes.PolicyRecord memory policy = GovProvTypes.PolicyRecord({
            policyHash: keccak256("policy:v1"),
            parentPolicyHash: bytes32(0),
            metadataHash: keccak256("metadata:policy:v1"),
            scopeHash: keccak256("scope:runbook_update"),
            status: GovProvTypes.PolicyStatus.REGISTERED,
            registeredBy: address(0xB0B),
            registeredAt: 11,
            activatedAt: 0,
            supersededAt: 0,
            revokedAt: 0,
            supersededByPolicyHash: bytes32(0),
            revocationReasonHash: bytes32(0)
        });

        GovProvTypes.AttestationRecord memory attestation = GovProvTypes.AttestationRecord({
            attestationHash: keccak256("attestation:action"),
            attestationTypeHash: keccak256("ACTION_PROPOSAL_ATTESTATION"),
            subjectHash: keccak256("action:001"),
            actor: actor.actor,
            policyHash: policy.policyHash,
            parentRoot: bytes32(0),
            metadataHash: keccak256("metadata:attestation:action"),
            scopeHash: policy.scopeHash,
            anchoredAt: 12,
            exists: true
        });

        GovProvTypes.ApprovalRecord memory approval = GovProvTypes.ApprovalRecord({
            approvalHash: keccak256("attestation:approval"),
            actionHash: attestation.attestationHash,
            artifactHash: keccak256("artifact:001"),
            policyDecisionHash: keccak256("policy-decision:001"),
            proposer: actor.actor,
            approver: address(0xA200),
            approvalRole: GovProvRoles.APPROVER_ROLE,
            status: GovProvTypes.ApprovalStatus.APPROVED,
            approvedAt: 13,
            expiresAt: 0,
            reasonHash: bytes32(0)
        });

        GovProvTypes.DeploymentRecord memory deployment = GovProvTypes.DeploymentRecord({
            deploymentIdHash: keccak256("deployment:001"),
            deploymentAttestationHash: keccak256("attestation:deployment"),
            actionHash: attestation.attestationHash,
            artifactHash: approval.artifactHash,
            policyHash: policy.policyHash,
            approvalRoot: keccak256("approval-root:001"),
            environmentHash: keccak256("environment:staging"),
            deployer: address(0xD100),
            status: GovProvTypes.DeploymentStatus.RECORDED,
            deployedAt: 14,
            revokedAt: 0,
            revocationReasonHash: bytes32(0)
        });

        GovProvTypes.ContractRecord memory registeredContract = GovProvTypes.ContractRecord({
            nameHash: keccak256("contract:deployment-registry"),
            contractAddress: address(0xD370),
            versionHash: keccak256("contract-version:v1"),
            sourceHash: keccak256("source:deployment-registry:v1"),
            abiHash: keccak256("abi:deployment-registry:v1"),
            metadataHash: keccak256("metadata:deployment-registry:v1"),
            status: GovProvTypes.ContractStatus.REGISTERED,
            registeredBy: address(0xA11CE),
            registeredAt: 15,
            activatedAt: 0,
            supersededAt: 0,
            supersededByContractAddress: address(0)
        });

        GovProvTypes.ContractSetRecord memory contractSet = GovProvTypes.ContractSetRecord({
            contractSetId: keccak256("contract-set:v1"),
            metadataHash: keccak256("metadata:contract-set:v1"),
            activatedAt: 16,
            activatedBy: address(0xA11CE),
            active: true
        });

        assertEq(actor.actor, address(0xA11CE));
        assertEq(uint8(actor.actorType), uint8(GovProvTypes.ActorType.AGENT));
        assertEq(policy.parentPolicyHash, bytes32(0));
        assertEq(attestation.policyHash, policy.policyHash);
        assertTrue(attestation.exists);
        assertEq(approval.actionHash, attestation.attestationHash);
        assertEq(approval.policyDecisionHash, keccak256("policy-decision:001"));
        assertEq(uint8(approval.status), uint8(GovProvTypes.ApprovalStatus.APPROVED));
        assertEq(deployment.deploymentAttestationHash, keccak256("attestation:deployment"));
        assertEq(deployment.environmentHash, keccak256("environment:staging"));
        assertEq(uint8(deployment.status), uint8(GovProvTypes.DeploymentStatus.RECORDED));
        assertEq(registeredContract.nameHash, keccak256("contract:deployment-registry"));
        assertEq(registeredContract.sourceHash, keccak256("source:deployment-registry:v1"));
        assertEq(registeredContract.abiHash, keccak256("abi:deployment-registry:v1"));
        assertEq(contractSet.contractSetId, keccak256("contract-set:v1"));
        assertTrue(contractSet.active);
    }

    function testValidationAllowsNonzeroValues() public view {
        validation.requireNonZeroAddress(address(0xA11CE));
        validation.requireNonZeroHash(keccak256("nonzero"), "actorIdHash");
    }

    function testValidationRejectsZeroAddress() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        validation.requireNonZeroAddress(address(0));
    }

    function testValidationRejectsZeroHashWithFieldName() public {
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "actorIdHash"));
        validation.requireNonZeroHash(bytes32(0), "actorIdHash");
    }
}
