// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract DeploymentRegistryTest is Test {
    ActorRegistry private actorRegistry;
    ApprovalRegistry private approvalRegistry;
    DeploymentRegistry private deploymentRegistry;
    PolicyRegistry private policyRegistry;
    ProvenanceRegistry private provenanceRegistry;

    address private governanceAdmin = address(0xA11CE);
    address private policyAdmin = address(0xBEEF);
    address private ledgerWriter = address(0x1ED9E);
    address private proposer = address(0xA100);
    address private approver = address(0xA200);
    address private deployer = address(0xD100);
    address private nonDeployer = address(0xCAFE);

    bytes32 private policyHash = keccak256("policy:v1");
    bytes32 private policyMetadataHash = keccak256("metadata:policy:v1");
    bytes32 private scopeHash = keccak256("scope:deployment");
    bytes32 private actionHash = keccak256("attestation:action:001");
    bytes32 private approvalHash = keccak256("attestation:approval:001");
    bytes32 private deploymentIdHash = keccak256("deployment:001");
    bytes32 private deploymentAttestationHash = keccak256("attestation:deployment:001");
    bytes32 private artifactHash = keccak256("artifact:runbook:001");
    bytes32 private policyDecisionHash = keccak256("policy-decision:001");
    bytes32 private approvalRoot = keccak256("approval-root:001");
    bytes32 private environmentHash = keccak256("environment:staging");
    bytes32 private reasonHash = keccak256("reason:test");
    bytes32 private metadataHash = keccak256("metadata:attestation");

    event DeploymentRecorded(
        bytes32 indexed deploymentIdHash,
        bytes32 indexed deploymentAttestationHash,
        bytes32 indexed actionHash,
        bytes32 artifactHash,
        bytes32 policyHash,
        bytes32 approvalRoot,
        bytes32 environmentHash,
        address deployer
    );
    event DeploymentRevoked(
        bytes32 indexed deploymentIdHash, bytes32 reasonHash, address revokedBy
    );

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        policyRegistry = new PolicyRegistry(actorRegistry);
        provenanceRegistry = new ProvenanceRegistry(actorRegistry, policyRegistry);
        approvalRegistry = new ApprovalRegistry(actorRegistry, provenanceRegistry);
        deploymentRegistry = new DeploymentRegistry(
            actorRegistry, policyRegistry, provenanceRegistry, approvalRegistry
        );

        _registerActor(policyAdmin, "actor:policy-admin", GovProvTypes.ActorType.HUMAN);
        _registerActor(ledgerWriter, "actor:ledger-writer", GovProvTypes.ActorType.SERVICE);
        _registerActor(proposer, "actor:agent-alpha", GovProvTypes.ActorType.AGENT);
        _registerActor(approver, "actor:approver-editor", GovProvTypes.ActorType.HUMAN);
        _registerActor(deployer, "actor:deployer", GovProvTypes.ActorType.HUMAN);
        _registerActor(nonDeployer, "actor:non-deployer", GovProvTypes.ActorType.HUMAN);

        vm.startPrank(governanceAdmin);
        actorRegistry.grantGovRole(policyAdmin, GovProvRoles.POLICY_ADMIN_ROLE);
        actorRegistry.grantGovRole(ledgerWriter, GovProvRoles.LEDGER_WRITER_ROLE);
        actorRegistry.grantGovRole(proposer, GovProvRoles.AGENT_ROLE);
        actorRegistry.grantGovRole(approver, GovProvRoles.APPROVER_ROLE);
        actorRegistry.grantGovRole(deployer, GovProvRoles.DEPLOYER_ROLE);
        vm.stopPrank();

        vm.prank(policyAdmin);
        policyRegistry.registerPolicy(policyHash, bytes32(0), policyMetadataHash, scopeHash);

        _anchorAction(actionHash);
        _anchorApproval(approvalHash, approver);
        _recordApproval(artifactHash);
        _anchorDeployment(deploymentAttestationHash, deployer);
    }

    function testConstructorRejectsZeroActorRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new DeploymentRegistry(
            ActorRegistry(address(0)), policyRegistry, provenanceRegistry, approvalRegistry
        );
    }

    function testConstructorRejectsZeroPolicyRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new DeploymentRegistry(
            actorRegistry, PolicyRegistry(address(0)), provenanceRegistry, approvalRegistry
        );
    }

    function testConstructorRejectsZeroProvenanceRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new DeploymentRegistry(
            actorRegistry, policyRegistry, ProvenanceRegistry(address(0)), approvalRegistry
        );
    }

    function testConstructorRejectsZeroApprovalRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new DeploymentRegistry(
            actorRegistry, policyRegistry, provenanceRegistry, ApprovalRegistry(address(0))
        );
    }

    function testDeployerCanRecordDeploymentWithValidApproval() public {
        vm.expectEmit(true, true, true, true, address(deploymentRegistry));
        emit DeploymentRecorded(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash,
            deployer
        );

        _recordDeploymentAs(deployer, deploymentIdHash, deploymentAttestationHash, artifactHash);

        assertTrue(deploymentRegistry.deploymentExists(deploymentIdHash));
        assertEq(
            deploymentRegistry.getDeploymentByAttestation(deploymentAttestationHash),
            deploymentIdHash
        );

        GovProvTypes.DeploymentRecord memory record =
            deploymentRegistry.getDeployment(deploymentIdHash);
        assertEq(record.deploymentIdHash, deploymentIdHash);
        assertEq(record.deploymentAttestationHash, deploymentAttestationHash);
        assertEq(record.actionHash, actionHash);
        assertEq(record.artifactHash, artifactHash);
        assertEq(record.policyHash, policyHash);
        assertEq(record.approvalRoot, approvalRoot);
        assertEq(record.environmentHash, environmentHash);
        assertEq(record.deployer, deployer);
        assertEq(uint8(record.status), uint8(GovProvTypes.DeploymentStatus.RECORDED));
        assertGt(record.deployedAt, 0);
    }

    function testLedgerWriterCanRecordDeployment() public {
        _recordDeploymentAs(ledgerWriter, deploymentIdHash, deploymentAttestationHash, artifactHash);

        GovProvTypes.DeploymentRecord memory record =
            deploymentRegistry.getDeployment(deploymentIdHash);
        assertEq(record.deployer, ledgerWriter);
    }

    function testNonDeployerOrLedgerWriterCannotRecordDeployment() public {
        vm.prank(nonDeployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, nonDeployer, GovProvRoles.DEPLOYER_ROLE
            )
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentWithUnknownActionReverts() public {
        bytes32 unknownActionHash = keccak256("attestation:action:missing");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.AttestationNotFound.selector, unknownActionHash)
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            unknownActionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentWithUnknownDeploymentAttestationReverts() public {
        bytes32 unknownDeploymentAttestationHash = keccak256("attestation:deployment:missing");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.AttestationNotFound.selector, unknownDeploymentAttestationHash
            )
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            unknownDeploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentWithUnknownPolicyReverts() public {
        bytes32 unknownPolicyHash = keccak256("policy:missing");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.PolicyNotFound.selector, unknownPolicyHash)
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            unknownPolicyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentWithoutApprovalReverts() public {
        bytes32 unapprovedActionHash = keccak256("attestation:action:unapproved");
        _anchorAction(unapprovedActionHash);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ArtifactApprovalMissing.selector, unapprovedActionHash, artifactHash
            )
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            unapprovedActionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentWithWrongArtifactHashReverts() public {
        bytes32 wrongArtifactHash = keccak256("artifact:wrong");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ArtifactApprovalMissing.selector, actionHash, wrongArtifactHash
            )
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            wrongArtifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testZeroDeploymentHashesRevert() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "deploymentIdHash"));
        deploymentRegistry.recordDeployment(
            bytes32(0),
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "deploymentAttestationHash")
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            bytes32(0),
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testZeroActionArtifactPolicyApprovalRootAndEnvironmentHashesRevert() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "actionHash"));
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            bytes32(0),
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "artifactHash"));
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            bytes32(0),
            policyHash,
            approvalRoot,
            environmentHash
        );

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "policyHash"));
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            bytes32(0),
            approvalRoot,
            environmentHash
        );

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "approvalRoot"));
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            bytes32(0),
            environmentHash
        );

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "environmentHash"));
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            bytes32(0)
        );
    }

    function testDuplicateDeploymentIdReverts() public {
        _recordDeploymentAs(deployer, deploymentIdHash, deploymentAttestationHash, artifactHash);

        bytes32 secondDeploymentAttestationHash = keccak256("attestation:deployment:002");
        _anchorDeployment(secondDeploymentAttestationHash, deployer);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.DeploymentAlreadyRecorded.selector, deploymentIdHash
            )
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            secondDeploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDuplicateDeploymentAttestationReverts() public {
        _recordDeploymentAs(deployer, deploymentIdHash, deploymentAttestationHash, artifactHash);

        bytes32 secondDeploymentIdHash = keccak256("deployment:002");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.DeploymentAlreadyRecorded.selector, deploymentIdHash
            )
        );
        deploymentRegistry.recordDeployment(
            secondDeploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testRevocationWorks() public {
        _recordDeploymentAs(deployer, deploymentIdHash, deploymentAttestationHash, artifactHash);

        vm.expectEmit(true, false, false, true, address(deploymentRegistry));
        emit DeploymentRevoked(deploymentIdHash, reasonHash, governanceAdmin);

        vm.prank(governanceAdmin);
        deploymentRegistry.revokeDeployment(deploymentIdHash, reasonHash);

        GovProvTypes.DeploymentRecord memory record =
            deploymentRegistry.getDeployment(deploymentIdHash);
        assertEq(uint8(record.status), uint8(GovProvTypes.DeploymentStatus.REVOKED));
        assertEq(record.revocationReasonHash, reasonHash);
        assertGt(record.revokedAt, 0);
    }

    function testNonGovernanceAdminCannotRevokeDeployment() public {
        _recordDeploymentAs(deployer, deploymentIdHash, deploymentAttestationHash, artifactHash);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, deployer, GovProvRoles.GOVERNANCE_ADMIN_ROLE
            )
        );
        deploymentRegistry.revokeDeployment(deploymentIdHash, reasonHash);
    }

    function testGetMissingDeploymentReverts() public {
        bytes32 missingDeploymentIdHash = keccak256("deployment:missing");

        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.DeploymentNotFound.selector, missingDeploymentIdHash
            )
        );
        deploymentRegistry.getDeployment(missingDeploymentIdHash);
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

    function _recordApproval(bytes32 targetArtifactHash) private {
        vm.prank(approver);
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            targetArtifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );
    }

    function _recordDeploymentAs(
        address caller,
        bytes32 targetDeploymentIdHash,
        bytes32 targetDeploymentAttestationHash,
        bytes32 targetArtifactHash
    ) private {
        vm.prank(caller);
        deploymentRegistry.recordDeployment(
            targetDeploymentIdHash,
            targetDeploymentAttestationHash,
            actionHash,
            targetArtifactHash,
            policyHash,
            approvalRoot,
            environmentHash
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

    function _anchorApproval(bytes32 targetApprovalHash, address targetApprover) private {
        _anchorAttestation(
            targetApprovalHash,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            targetApprovalHash,
            targetApprover
        );
    }

    function _anchorDeployment(bytes32 targetDeploymentAttestationHash, address targetDeployer)
        private
    {
        _anchorAttestation(
            targetDeploymentAttestationHash,
            provenanceRegistry.DEPLOYMENT_ATTESTATION(),
            deploymentIdHash,
            targetDeployer
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
