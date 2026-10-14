// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract ApprovalRegistryTest is Test {
    ActorRegistry private actorRegistry;
    ApprovalRegistry private approvalRegistry;
    PolicyRegistry private policyRegistry;
    ProvenanceRegistry private provenanceRegistry;

    address private governanceAdmin = address(0xA11CE);
    address private policyAdmin = address(0xBEEF);
    address private ledgerWriter = address(0x1ED9E);
    address private proposer = address(0xA100);
    address private approver = address(0xA200);
    address private securityApprover = address(0xA300);
    address private nonApprover = address(0xCAFE);

    bytes32 private policyHash = keccak256("policy:v1");
    bytes32 private policyMetadataHash = keccak256("metadata:policy:v1");
    bytes32 private scopeHash = keccak256("scope:runbook_update");
    bytes32 private actionHash = keccak256("attestation:action:001");
    bytes32 private approvalHash = keccak256("attestation:approval:001");
    bytes32 private secondApprovalHash = keccak256("attestation:approval:002");
    bytes32 private artifactHash = keccak256("artifact:runbook:001");
    bytes32 private policyDecisionHash = keccak256("policy-decision:001");
    bytes32 private reasonHash = keccak256("reason:test");
    bytes32 private metadataHash = keccak256("metadata:attestation");

    event ApprovalRecorded(
        bytes32 indexed actionHash,
        bytes32 indexed approvalHash,
        address indexed approver,
        bytes32 approvalRole,
        bytes32 artifactHash,
        bytes32 policyDecisionHash,
        address proposer,
        uint64 expiresAt
    );
    event ApprovalRejected(
        bytes32 indexed actionHash,
        bytes32 indexed approvalHash,
        address indexed approver,
        bytes32 approvalRole,
        bytes32 reasonHash
    );
    event ApprovalRevoked(
        bytes32 indexed approvalHash,
        address indexed approver,
        bytes32 reasonHash,
        address revokedBy
    );

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        policyRegistry = new PolicyRegistry(actorRegistry);
        provenanceRegistry = new ProvenanceRegistry(actorRegistry, policyRegistry);
        approvalRegistry = new ApprovalRegistry(actorRegistry, provenanceRegistry);

        _registerActor(policyAdmin, "actor:policy-admin", GovProvTypes.ActorType.HUMAN);
        _registerActor(ledgerWriter, "actor:ledger-writer", GovProvTypes.ActorType.SERVICE);
        _registerActor(proposer, "actor:agent-alpha", GovProvTypes.ActorType.AGENT);
        _registerActor(approver, "actor:approver-editor", GovProvTypes.ActorType.HUMAN);
        _registerActor(securityApprover, "actor:approver-security", GovProvTypes.ActorType.HUMAN);
        _registerActor(nonApprover, "actor:non-approver", GovProvTypes.ActorType.HUMAN);

        vm.startPrank(governanceAdmin);
        actorRegistry.grantGovRole(policyAdmin, GovProvRoles.POLICY_ADMIN_ROLE);
        actorRegistry.grantGovRole(ledgerWriter, GovProvRoles.LEDGER_WRITER_ROLE);
        actorRegistry.grantGovRole(proposer, GovProvRoles.AGENT_ROLE);
        actorRegistry.grantGovRole(approver, GovProvRoles.APPROVER_ROLE);
        actorRegistry.grantGovRole(securityApprover, GovProvRoles.SECURITY_APPROVER_ROLE);
        vm.stopPrank();

        vm.prank(policyAdmin);
        policyRegistry.registerPolicy(policyHash, bytes32(0), policyMetadataHash, scopeHash);

        _anchorAction(actionHash);
        _anchorApproval(approvalHash);
    }

    function testConstructorRejectsZeroActorRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new ApprovalRegistry(ActorRegistry(address(0)), provenanceRegistry);
    }

    function testConstructorRejectsZeroProvenanceRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new ApprovalRegistry(actorRegistry, ProvenanceRegistry(address(0)));
    }

    function testApproverCanRecordApprovalForAnchoredAction() public {
        vm.expectEmit(true, true, true, true, address(approvalRegistry));
        emit ApprovalRecorded(
            actionHash,
            approvalHash,
            approver,
            GovProvRoles.APPROVER_ROLE,
            artifactHash,
            policyDecisionHash,
            proposer,
            0
        );

        _recordApproval();

        assertTrue(approvalRegistry.approvalExists(approvalHash));
        assertTrue(approvalRegistry.isApprovalValid(approvalHash));
        assertEq(approvalRegistry.getApprovalCount(actionHash), 1);
        assertEq(approvalRegistry.getApprovalByActionAt(actionHash, 0), approvalHash);

        GovProvTypes.ApprovalRecord memory record = approvalRegistry.getApproval(approvalHash);
        assertEq(record.approvalHash, approvalHash);
        assertEq(record.actionHash, actionHash);
        assertEq(record.artifactHash, artifactHash);
        assertEq(record.policyDecisionHash, policyDecisionHash);
        assertEq(record.proposer, proposer);
        assertEq(record.approver, approver);
        assertEq(record.approvalRole, GovProvRoles.APPROVER_ROLE);
        assertEq(uint8(record.status), uint8(GovProvTypes.ApprovalStatus.APPROVED));
    }

    function testNonApproverCannotRecordApproval() public {
        vm.prank(nonApprover);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, nonApprover, GovProvRoles.APPROVER_ROLE
            )
        );
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testUnsupportedApprovalRoleReverts() public {
        vm.prank(approver);
        vm.expectRevert(GovProvErrors.InvalidStatusTransition.selector);
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.DEPLOYER_ROLE,
            0
        );
    }

    function testApprovalByProposerReverts() public {
        vm.prank(governanceAdmin);
        actorRegistry.grantGovRole(proposer, GovProvRoles.APPROVER_ROLE);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.SeparationOfDutiesViolation.selector, proposer, proposer
            )
        );
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testApprovalForUnknownActionReverts() public {
        bytes32 unknownActionHash = keccak256("attestation:action:missing");

        vm.prank(approver);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.AttestationNotFound.selector, unknownActionHash)
        );
        approvalRegistry.recordApproval(
            unknownActionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testApprovalForUnknownApprovalAttestationReverts() public {
        bytes32 unknownApprovalHash = keccak256("attestation:approval:missing");

        vm.prank(approver);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.AttestationNotFound.selector, unknownApprovalHash)
        );
        approvalRegistry.recordApproval(
            actionHash,
            unknownApprovalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testApprovalForZeroArtifactHashReverts() public {
        vm.prank(approver);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "artifactHash"));
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            bytes32(0),
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testZeroActionApprovalAndPolicyDecisionHashesRevert() public {
        vm.prank(approver);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "actionHash"));
        approvalRegistry.recordApproval(
            bytes32(0),
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );

        vm.prank(approver);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "approvalHash"));
        approvalRegistry.recordApproval(
            actionHash,
            bytes32(0),
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );

        vm.prank(approver);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "policyDecisionHash")
        );
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            bytes32(0),
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testDuplicateApprovalHashReverts() public {
        _recordApproval();

        vm.prank(approver);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ApprovalAlreadyRecorded.selector, approvalHash)
        );
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testSuspendedApproverCannotApprove() public {
        vm.prank(governanceAdmin);
        actorRegistry.suspendActor(approver, reasonHash);

        vm.prank(approver);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, approver));
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testRevokedApproverCannotApprove() public {
        vm.prank(governanceAdmin);
        actorRegistry.revokeActor(approver, reasonHash);

        vm.prank(approver);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, approver));
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function testRejectionCanBeRecordedWithReasonHash() public {
        vm.expectEmit(true, true, true, true, address(approvalRegistry));
        emit ApprovalRejected(
            actionHash, approvalHash, approver, GovProvRoles.APPROVER_ROLE, reasonHash
        );

        vm.prank(approver);
        approvalRegistry.recordRejection(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            reasonHash
        );

        GovProvTypes.ApprovalRecord memory record = approvalRegistry.getApproval(approvalHash);
        assertEq(uint8(record.status), uint8(GovProvTypes.ApprovalStatus.REJECTED));
        assertEq(record.reasonHash, reasonHash);
        assertFalse(approvalRegistry.isApprovalValid(approvalHash));
    }

    function testApprovalRevocationWorks() public {
        _recordApproval();

        vm.expectEmit(true, true, false, true, address(approvalRegistry));
        emit ApprovalRevoked(approvalHash, approver, reasonHash, approver);

        vm.prank(approver);
        approvalRegistry.revokeApproval(approvalHash, reasonHash);

        GovProvTypes.ApprovalRecord memory record = approvalRegistry.getApproval(approvalHash);
        assertEq(uint8(record.status), uint8(GovProvTypes.ApprovalStatus.REVOKED));
        assertEq(record.reasonHash, reasonHash);
    }

    function testGovernanceAdminCanRevokeApproval() public {
        _recordApproval();

        vm.prank(governanceAdmin);
        approvalRegistry.revokeApproval(approvalHash, reasonHash);

        assertFalse(approvalRegistry.isApprovalValid(approvalHash));
    }

    function testRevokedApprovalIsNotValid() public {
        _recordApproval();
        vm.prank(approver);
        approvalRegistry.revokeApproval(approvalHash, reasonHash);

        assertFalse(approvalRegistry.isApprovalValid(approvalHash));
        assertFalse(
            approvalRegistry.hasValidApprovalForArtifact(
                actionHash, artifactHash, GovProvRoles.APPROVER_ROLE
            )
        );
    }

    function testValidApprovalLookupByActionArtifactAndRoleWorks() public {
        _recordApproval();
        _anchorApproval(secondApprovalHash);

        vm.prank(securityApprover);
        approvalRegistry.recordApproval(
            actionHash,
            secondApprovalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.SECURITY_APPROVER_ROLE,
            0
        );

        assertTrue(
            approvalRegistry.hasValidApprovalForArtifact(
                actionHash, artifactHash, GovProvRoles.APPROVER_ROLE
            )
        );
        assertTrue(
            approvalRegistry.hasValidApprovalForArtifact(
                actionHash, artifactHash, GovProvRoles.SECURITY_APPROVER_ROLE
            )
        );
        assertFalse(
            approvalRegistry.hasValidApprovalForArtifact(
                actionHash, keccak256("artifact:missing"), GovProvRoles.APPROVER_ROLE
            )
        );
        assertEq(approvalRegistry.getApprovalCount(actionHash), 2);
        assertEq(approvalRegistry.getApprovalByActionAt(actionHash, 1), secondApprovalHash);
    }

    function testExpiredApprovalIsNotValid() public {
        vm.warp(100);
        vm.prank(approver);
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            101
        );

        assertTrue(approvalRegistry.isApprovalValid(approvalHash));
        vm.warp(102);
        assertFalse(approvalRegistry.isApprovalValid(approvalHash));
    }

    function testGetMissingApprovalReverts() public {
        bytes32 missingApprovalHash = keccak256("approval:missing");

        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ApprovalNotFound.selector, missingApprovalHash)
        );
        approvalRegistry.getApproval(missingApprovalHash);
    }

    function _registerActor(address actor, string memory actorId, GovProvTypes.ActorType actorType)
        private
    {
        vm.prank(governanceAdmin);
        actorRegistry.registerActor(
            actor,
            keccak256(bytes(actorId)),
            actorType,
            keccak256(abi.encodePacked("metadata:", actorId))
        );
    }

    function _recordApproval() private {
        vm.prank(approver);
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            artifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function _anchorAction(bytes32 targetActionHash) private {
        _anchorAttestation(
            targetActionHash,
            provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
            targetActionHash,
            proposer
        );
    }

    function _anchorApproval(bytes32 targetApprovalHash) private {
        _anchorAttestation(
            targetApprovalHash,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            targetApprovalHash,
            approver
        );
    }

    function _anchorAttestation(
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor
    ) private {
        vm.prank(ledgerWriter);
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            actor,
            policyHash,
            bytes32(0),
            metadataHash,
            scopeHash
        );
    }
}
