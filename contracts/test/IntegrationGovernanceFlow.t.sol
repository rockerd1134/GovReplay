// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { ContractDirectory } from "../src/ContractDirectory.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract IntegrationGovernanceFlowTest is Test {
    ActorRegistry private actorRegistry;
    PolicyRegistry private policyRegistry;
    ProvenanceRegistry private provenanceRegistry;
    ApprovalRegistry private approvalRegistry;
    DeploymentRegistry private deploymentRegistry;
    ContractDirectory private contractDirectory;

    address private governanceAdmin = address(0xA11CE);
    address private policyAdmin = address(0xBEEF);
    address private ledgerWriter = address(0x1ED9E);
    address private proposer = address(0xA100);
    address private policyEvaluator = address(0xA150);
    address private approver = address(0xA200);
    address private deployer = address(0xD100);
    address private unregisteredActor = address(0xBAD);

    bytes32 private policyHash = keccak256("policy:v1:runbook");
    bytes32 private successorPolicyHash = keccak256("policy:v2:runbook");
    bytes32 private policyMetadataHash = keccak256("metadata:policy:v1:runbook");
    bytes32 private successorPolicyMetadataHash = keccak256("metadata:policy:v2:runbook");
    bytes32 private scopeHash = keccak256("scope:runbook-update");
    bytes32 private actionHash = keccak256("attestation:action:runbook:001");
    bytes32 private policyDecisionHash = keccak256("attestation:policy-decision:runbook:001");
    bytes32 private approvalHash = keccak256("attestation:approval:runbook:001");
    bytes32 private deploymentAttestationHash = keccak256("attestation:deployment:runbook:001");
    bytes32 private deploymentIdHash = keccak256("deployment:runbook:001");
    bytes32 private artifactHash = keccak256("artifact:runbook:001");
    bytes32 private approvalRoot = keccak256("approval-root:runbook:001");
    bytes32 private environmentHash = keccak256("environment:staging");
    bytes32 private metadataHash = keccak256("metadata:integration");
    bytes32 private versionHash = keccak256("contracts:phase1:v1");
    bytes32 private sourceHash = keccak256("source:phase1:v1");
    bytes32 private abiHash = keccak256("abi:phase1:v1");
    bytes32 private contractSetId = keccak256("contract-set:phase1:v1");

    bytes32 private actorRegistryNameHash = keccak256("ACTOR_REGISTRY");
    bytes32 private policyRegistryNameHash = keccak256("POLICY_REGISTRY");
    bytes32 private provenanceRegistryNameHash = keccak256("PROVENANCE_REGISTRY");
    bytes32 private approvalRegistryNameHash = keccak256("APPROVAL_REGISTRY");
    bytes32 private deploymentRegistryNameHash = keccak256("DEPLOYMENT_REGISTRY");
    bytes32 private contractDirectoryNameHash = keccak256("CONTRACT_DIRECTORY");

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        policyRegistry = new PolicyRegistry(actorRegistry);
        provenanceRegistry = new ProvenanceRegistry(actorRegistry, policyRegistry);
        approvalRegistry = new ApprovalRegistry(actorRegistry, provenanceRegistry);
        deploymentRegistry = new DeploymentRegistry(
            actorRegistry, policyRegistry, provenanceRegistry, approvalRegistry
        );
        contractDirectory = new ContractDirectory(actorRegistry);

        _registerPhaseOneActors();
        _grantPhaseOneRoles();
    }

    function testRecordsGovernedWorkflowAcrossPhaseOneRegistries() public {
        _registerAndActivatePolicy();
        _anchorHappyPathAttestations();

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

        vm.prank(deployer);
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );

        _registerAndActivateContractSet();

        assertEq(policyRegistry.getActivePolicy(scopeHash), policyHash);
        assertTrue(provenanceRegistry.attestationExists(actionHash));
        assertTrue(provenanceRegistry.attestationExists(policyDecisionHash));
        assertTrue(provenanceRegistry.attestationExists(approvalHash));
        assertTrue(provenanceRegistry.attestationExists(deploymentAttestationHash));
        assertEq(provenanceRegistry.getAttestationPolicy(actionHash), policyHash);
        assertEq(provenanceRegistry.getAttestationActor(policyDecisionHash), policyEvaluator);
        assertTrue(approvalRegistry.isApprovalValid(approvalHash));
        assertEq(approvalRegistry.getApprovalCount(actionHash), 1);
        assertEq(approvalRegistry.getApprovalByActionAt(actionHash, 0), approvalHash);

        GovProvTypes.ApprovalRecord memory approval = approvalRegistry.getApproval(approvalHash);
        assertEq(approval.actionHash, actionHash);
        assertEq(approval.artifactHash, artifactHash);
        assertEq(approval.policyDecisionHash, policyDecisionHash);
        assertEq(approval.proposer, proposer);
        assertEq(approval.approver, approver);
        assertEq(uint8(approval.status), uint8(GovProvTypes.ApprovalStatus.APPROVED));

        assertTrue(deploymentRegistry.deploymentExists(deploymentIdHash));
        assertEq(
            deploymentRegistry.getDeploymentByAttestation(deploymentAttestationHash),
            deploymentIdHash
        );
        GovProvTypes.DeploymentRecord memory deployment =
            deploymentRegistry.getDeployment(deploymentIdHash);
        assertEq(deployment.deploymentAttestationHash, deploymentAttestationHash);
        assertEq(deployment.actionHash, actionHash);
        assertEq(deployment.artifactHash, artifactHash);
        assertEq(deployment.policyHash, policyHash);
        assertEq(deployment.approvalRoot, approvalRoot);
        assertEq(deployment.environmentHash, environmentHash);
        assertEq(deployment.deployer, deployer);
        assertEq(uint8(deployment.status), uint8(GovProvTypes.DeploymentStatus.RECORDED));

        assertEq(contractDirectory.getActiveContractSet(), contractSetId);
        assertEq(
            contractDirectory.getContract(contractSetId, actorRegistryNameHash),
            address(actorRegistry)
        );
        assertEq(
            contractDirectory.getContract(contractSetId, deploymentRegistryNameHash),
            address(deploymentRegistry)
        );
        assertTrue(
            contractDirectory.isRegisteredContract(
                contractDirectoryNameHash, address(contractDirectory)
            )
        );
    }

    function testRecordsPolicyEvolutionAcrossGovernedDeployments() public {
        _registerAndActivatePolicy();
        _recordGovernedDeployment(
            actionHash,
            policyDecisionHash,
            approvalHash,
            deploymentAttestationHash,
            deploymentIdHash,
            artifactHash,
            approvalRoot,
            policyHash
        );

        bytes32 secondActionHash = keccak256("attestation:action:runbook:002");
        bytes32 secondPolicyDecisionHash = keccak256("attestation:policy-decision:runbook:002");
        bytes32 secondApprovalHash = keccak256("attestation:approval:runbook:002");
        bytes32 secondDeploymentAttestationHash = keccak256("attestation:deployment:runbook:002");
        bytes32 secondDeploymentIdHash = keccak256("deployment:runbook:002");
        bytes32 secondArtifactHash = keccak256("artifact:runbook:002");
        bytes32 secondApprovalRoot = keccak256("approval-root:runbook:002");

        vm.startPrank(policyAdmin);
        policyRegistry.registerPolicy(
            successorPolicyHash, policyHash, successorPolicyMetadataHash, scopeHash
        );
        policyRegistry.activatePolicy(successorPolicyHash);
        vm.stopPrank();

        _recordGovernedDeployment(
            secondActionHash,
            secondPolicyDecisionHash,
            secondApprovalHash,
            secondDeploymentAttestationHash,
            secondDeploymentIdHash,
            secondArtifactHash,
            secondApprovalRoot,
            successorPolicyHash
        );

        assertEq(policyRegistry.getActivePolicy(scopeHash), successorPolicyHash);
        assertFalse(policyRegistry.isPolicyActive(policyHash));
        assertTrue(policyRegistry.isPolicyActive(successorPolicyHash));

        GovProvTypes.PolicyRecord memory firstPolicy = policyRegistry.getPolicy(policyHash);
        assertEq(uint8(firstPolicy.status), uint8(GovProvTypes.PolicyStatus.SUPERSEDED));
        assertEq(firstPolicy.supersededByPolicyHash, successorPolicyHash);

        GovProvTypes.PolicyRecord memory secondPolicy =
            policyRegistry.getPolicy(successorPolicyHash);
        assertEq(uint8(secondPolicy.status), uint8(GovProvTypes.PolicyStatus.ACTIVE));
        assertEq(secondPolicy.parentPolicyHash, policyHash);

        GovProvTypes.DeploymentRecord memory firstDeployment =
            deploymentRegistry.getDeployment(deploymentIdHash);
        GovProvTypes.DeploymentRecord memory secondDeployment =
            deploymentRegistry.getDeployment(secondDeploymentIdHash);

        assertEq(firstDeployment.policyHash, policyHash);
        assertEq(firstDeployment.actionHash, actionHash);
        assertEq(firstDeployment.artifactHash, artifactHash);
        assertEq(secondDeployment.policyHash, successorPolicyHash);
        assertEq(secondDeployment.actionHash, secondActionHash);
        assertEq(secondDeployment.artifactHash, secondArtifactHash);

        assertEq(provenanceRegistry.getAttestationPolicy(actionHash), policyHash);
        assertEq(
            provenanceRegistry.getAttestationPolicy(secondActionHash), successorPolicyHash
        );
        assertTrue(approvalRegistry.isApprovalValid(approvalHash));
        assertTrue(approvalRegistry.isApprovalValid(secondApprovalHash));
    }

    function testDeploymentRecordingFailsWhenActionAttestationIsMissing() public {
        _registerAndActivatePolicy();
        _anchorDeployment(deploymentAttestationHash);

        bytes32 missingActionHash = keccak256("attestation:action:missing");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.AttestationNotFound.selector, missingActionHash)
        );
        deploymentRegistry.recordDeployment(
            deploymentIdHash,
            deploymentAttestationHash,
            missingActionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash
        );
    }

    function testDeploymentRecordingFailsWhenApprovalIsMissingOrForWrongArtifact() public {
        _registerAndActivatePolicy();
        _anchorAction(actionHash);
        _anchorApproval(approvalHash);
        _anchorDeployment(deploymentAttestationHash);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ArtifactApprovalMissing.selector, actionHash, artifactHash
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

        bytes32 wrongArtifactHash = keccak256("artifact:wrong");
        vm.prank(approver);
        approvalRegistry.recordApproval(
            actionHash,
            approvalHash,
            wrongArtifactHash,
            policyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ArtifactApprovalMissing.selector, actionHash, artifactHash
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

    function testProvenanceAnchoringFailsForInactiveOrUnregisteredHeaderActor() public {
        _registerAndActivatePolicy();
        bytes32 actionProposalTypeHash = provenanceRegistry.ACTION_PROPOSAL_ATTESTATION();

        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ActorNotRegistered.selector, unregisteredActor)
        );
        provenanceRegistry.anchorAttestation(
            actionHash,
            actionProposalTypeHash,
            actionHash,
            unregisteredActor,
            policyHash,
            bytes32(0),
            metadataHash,
            scopeHash
        );

        vm.prank(governanceAdmin);
        actorRegistry.suspendActor(proposer, keccak256("reason:integration:suspended"));

        vm.prank(ledgerWriter);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, proposer));
        provenanceRegistry.anchorAttestation(
            actionHash,
            actionProposalTypeHash,
            actionHash,
            proposer,
            policyHash,
            bytes32(0),
            metadataHash,
            scopeHash
        );
    }

    function testContractSetActivationFailsForUnregisteredNameAddressPair() public {
        _registerContract(actorRegistryNameHash, address(actorRegistry));

        bytes32[] memory names = new bytes32[](2);
        names[0] = actorRegistryNameHash;
        names[1] = policyRegistryNameHash;

        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = address(actorRegistry);
        contractAddresses[1] = address(policyRegistry);

        vm.prank(governanceAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ContractNotFound.selector,
                policyRegistryNameHash,
                address(policyRegistry)
            )
        );
        contractDirectory.activateContractSet(contractSetId, metadataHash, names, contractAddresses);
    }

    function _registerPhaseOneActors() private {
        _registerActor(policyAdmin, "actor:policy-admin", GovProvTypes.ActorType.HUMAN);
        _registerActor(ledgerWriter, "actor:ledger-writer", GovProvTypes.ActorType.SERVICE);
        _registerActor(proposer, "actor:agent-proposer", GovProvTypes.ActorType.AGENT);
        _registerActor(policyEvaluator, "actor:policy-evaluator", GovProvTypes.ActorType.SERVICE);
        _registerActor(approver, "actor:approver", GovProvTypes.ActorType.HUMAN);
        _registerActor(deployer, "actor:deployer", GovProvTypes.ActorType.HUMAN);
        _registerActor(
            address(actorRegistry), "contract:actor-registry", GovProvTypes.ActorType.CONTRACT
        );
        _registerActor(
            address(policyRegistry), "contract:policy-registry", GovProvTypes.ActorType.CONTRACT
        );
        _registerActor(
            address(provenanceRegistry),
            "contract:provenance-registry",
            GovProvTypes.ActorType.CONTRACT
        );
        _registerActor(
            address(approvalRegistry), "contract:approval-registry", GovProvTypes.ActorType.CONTRACT
        );
        _registerActor(
            address(deploymentRegistry),
            "contract:deployment-registry",
            GovProvTypes.ActorType.CONTRACT
        );
        _registerActor(
            address(contractDirectory),
            "contract:contract-directory",
            GovProvTypes.ActorType.CONTRACT
        );
    }

    function _grantPhaseOneRoles() private {
        vm.startPrank(governanceAdmin);
        actorRegistry.grantGovRole(policyAdmin, GovProvRoles.POLICY_ADMIN_ROLE);
        actorRegistry.grantGovRole(ledgerWriter, GovProvRoles.LEDGER_WRITER_ROLE);
        actorRegistry.grantGovRole(proposer, GovProvRoles.AGENT_ROLE);
        actorRegistry.grantGovRole(policyEvaluator, GovProvRoles.POLICY_EVALUATOR_ROLE);
        actorRegistry.grantGovRole(approver, GovProvRoles.APPROVER_ROLE);
        actorRegistry.grantGovRole(deployer, GovProvRoles.DEPLOYER_ROLE);
        vm.stopPrank();
    }

    function _registerAndActivatePolicy() private {
        vm.startPrank(policyAdmin);
        policyRegistry.registerPolicy(policyHash, bytes32(0), policyMetadataHash, scopeHash);
        policyRegistry.activatePolicy(policyHash);
        vm.stopPrank();
    }

    function _recordGovernedDeployment(
        bytes32 targetActionHash,
        bytes32 targetPolicyDecisionHash,
        bytes32 targetApprovalHash,
        bytes32 targetDeploymentAttestationHash,
        bytes32 targetDeploymentIdHash,
        bytes32 targetArtifactHash,
        bytes32 targetApprovalRoot,
        bytes32 targetPolicyHash
    ) private {
        _anchorAttestationForPolicy(
            targetActionHash,
            provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
            targetActionHash,
            proposer,
            bytes32(0),
            targetPolicyHash
        );
        _anchorAttestationForPolicy(
            targetPolicyDecisionHash,
            provenanceRegistry.POLICY_DECISION_ATTESTATION(),
            targetActionHash,
            policyEvaluator,
            targetActionHash,
            targetPolicyHash
        );
        _anchorAttestationForPolicy(
            targetApprovalHash,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            targetApprovalHash,
            approver,
            targetPolicyDecisionHash,
            targetPolicyHash
        );

        vm.prank(approver);
        approvalRegistry.recordApproval(
            targetActionHash,
            targetApprovalHash,
            targetArtifactHash,
            targetPolicyDecisionHash,
            proposer,
            GovProvRoles.APPROVER_ROLE,
            0
        );

        _anchorAttestationForPolicy(
            targetDeploymentAttestationHash,
            provenanceRegistry.DEPLOYMENT_ATTESTATION(),
            targetDeploymentIdHash,
            deployer,
            targetApprovalRoot,
            targetPolicyHash
        );

        vm.prank(deployer);
        deploymentRegistry.recordDeployment(
            targetDeploymentIdHash,
            targetDeploymentAttestationHash,
            targetActionHash,
            targetArtifactHash,
            targetPolicyHash,
            targetApprovalRoot,
            environmentHash
        );
    }

    function _anchorHappyPathAttestations() private {
        _anchorAction(actionHash);
        _anchorAttestation(
            policyDecisionHash,
            provenanceRegistry.POLICY_DECISION_ATTESTATION(),
            actionHash,
            policyEvaluator,
            actionHash
        );
        _anchorApproval(approvalHash);
        _anchorDeployment(deploymentAttestationHash);
    }

    function _anchorAction(bytes32 targetActionHash) private {
        _anchorAttestation(
            targetActionHash,
            provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
            targetActionHash,
            proposer,
            bytes32(0)
        );
    }

    function _anchorApproval(bytes32 targetApprovalHash) private {
        _anchorAttestation(
            targetApprovalHash,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            targetApprovalHash,
            approver,
            policyDecisionHash
        );
    }

    function _anchorDeployment(bytes32 targetDeploymentAttestationHash) private {
        _anchorAttestation(
            targetDeploymentAttestationHash,
            provenanceRegistry.DEPLOYMENT_ATTESTATION(),
            deploymentIdHash,
            deployer,
            approvalRoot
        );
    }

    function _anchorAttestation(
        bytes32 targetAttestationHash,
        bytes32 targetTypeHash,
        bytes32 targetSubjectHash,
        address targetActor,
        bytes32 targetParentRoot
    ) private {
        _anchorAttestationForPolicy(
            targetAttestationHash,
            targetTypeHash,
            targetSubjectHash,
            targetActor,
            targetParentRoot,
            policyHash
        );
    }

    function _anchorAttestationForPolicy(
        bytes32 targetAttestationHash,
        bytes32 targetTypeHash,
        bytes32 targetSubjectHash,
        address targetActor,
        bytes32 targetParentRoot,
        bytes32 targetPolicyHash
    ) private {
        vm.prank(ledgerWriter);
        provenanceRegistry.anchorAttestation(
            targetAttestationHash,
            targetTypeHash,
            targetSubjectHash,
            targetActor,
            targetPolicyHash,
            targetParentRoot,
            metadataHash,
            scopeHash
        );
    }

    function _registerAndActivateContractSet() private {
        _registerContract(actorRegistryNameHash, address(actorRegistry));
        _registerContract(policyRegistryNameHash, address(policyRegistry));
        _registerContract(provenanceRegistryNameHash, address(provenanceRegistry));
        _registerContract(approvalRegistryNameHash, address(approvalRegistry));
        _registerContract(deploymentRegistryNameHash, address(deploymentRegistry));
        _registerContract(contractDirectoryNameHash, address(contractDirectory));

        bytes32[] memory names = new bytes32[](6);
        names[0] = actorRegistryNameHash;
        names[1] = policyRegistryNameHash;
        names[2] = provenanceRegistryNameHash;
        names[3] = approvalRegistryNameHash;
        names[4] = deploymentRegistryNameHash;
        names[5] = contractDirectoryNameHash;

        address[] memory contractAddresses = new address[](6);
        contractAddresses[0] = address(actorRegistry);
        contractAddresses[1] = address(policyRegistry);
        contractAddresses[2] = address(provenanceRegistry);
        contractAddresses[3] = address(approvalRegistry);
        contractAddresses[4] = address(deploymentRegistry);
        contractAddresses[5] = address(contractDirectory);

        vm.prank(governanceAdmin);
        contractDirectory.activateContractSet(contractSetId, metadataHash, names, contractAddresses);
    }

    function _registerContract(bytes32 nameHash, address contractAddress) private {
        vm.prank(governanceAdmin);
        contractDirectory.registerContract(
            nameHash, contractAddress, versionHash, sourceHash, abiHash, metadataHash
        );
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
}
