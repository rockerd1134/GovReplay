// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract S1BesuScenario is Script {
    address private constant GOVERNANCE_ADMIN = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
    address private constant RUNBOOK_AUTHOR = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    address private constant POLICY_SERVICE = 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69;
    address private constant DOCUMENTATION_PUBLISHER = 0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718;

    bytes32 private constant DEFAULT_SCOPE = keccak256("scope:default");
    bytes32 private constant DELIVERY_POLICY_V1 = keccak256("govprov:policy:delivery-v1");
    bytes32 private constant APPROVAL_ROLE = GovProvRoles.APPROVER_ROLE;

    bytes32 private constant OBSERVATION_HASH = 0xb3b38e2dcb3a03c5b99f3f6269847a3272df587ebd450fbc8ee5efe7b0aaf0eb;
    bytes32 private constant EVIDENCE_HASH = 0x34e3bfda0c60e64a14af392c17a1d700abec9de55ca310fa52bdfc22e5aeb810;
    bytes32 private constant POLICY_DECISION_HASH = 0x42da926c155cfe5af5c4dfea05a4ee998c6d7532496c30ab2b0d5ae22a9d1005;
    bytes32 private constant ACTION_HASH = 0x82403b5919a05d81379155df45030de0123b10027a21dab4f9b833ba389acfcb;
    bytes32 private constant APPROVAL_HASH = 0x84760d019bbeb5b0fa50c34a129c9a851ece6d38d17dbc5744bfaa5ee1b1cbcb;
    bytes32 private constant ARTIFACT_HASH = 0x42a3d77799639097948a46e4b6530fe3496894256d7e183c216ec4da53c69c1b;
    bytes32 private constant DEPLOYMENT_ATTESTATION_HASH = 0x94a2084d258a4dd622f419a284459316d9fdc88d1d96362b707e757d8bcc0edd;

    bytes32 private constant OBSERVATION_SUBJECT_HASH = 0x25358e5d17bda7ea4d588f973400635e55b110aecc37252f9587755b2ebb02d9;
    bytes32 private constant EVIDENCE_SUBJECT_HASH = 0xf31027b61e4404e2cb584cb2e9a1bec7fbfc7fc4b1c901ce9fd529079d805712;
    bytes32 private constant POLICY_DECISION_SUBJECT_HASH = 0xa5ccafbf55d9852abbb97e13ac82ffa5ab05c39f2a25080021f27b1c7de414e7;
    bytes32 private constant ACTION_SUBJECT_HASH = 0x4c9999840c7116af0accb154a38a8cc4c42666c9d8599b437eec057da4ccfcac;
    bytes32 private constant APPROVAL_SUBJECT_HASH = 0x71c6d05c304002dd28fe66221ee1d90842561f9cab9a17fea8160c3b5589e36d;
    bytes32 private constant ARTIFACT_SUBJECT_HASH = 0x9a39c90f134c5c57255ee2668b618efe79220d78151189d08845557d630d910a;
    bytes32 private constant DEPLOYMENT_SUBJECT_HASH = 0x7a84cd4a9c8b593561a7535d06101d2390228f07b6abd87f7c54d824ee7ba2d9;
    bytes32 private constant DEPLOYMENT_ID_HASH = keccak256("deployment-S1-0001:local-attestation-linked");

    bytes32 private constant OBSERVATION_METADATA_HASH = keccak256("metadata:S1:observation");
    bytes32 private constant EVIDENCE_METADATA_HASH = keccak256("metadata:S1:evidence");
    bytes32 private constant POLICY_DECISION_METADATA_HASH = keccak256("metadata:S1:policy-decision");
    bytes32 private constant ACTION_METADATA_HASH = keccak256("metadata:S1:action");
    bytes32 private constant APPROVAL_METADATA_HASH = keccak256("metadata:S1:approval");
    bytes32 private constant ARTIFACT_METADATA_HASH = keccak256("metadata:S1:artifact");
    bytes32 private constant DEPLOYMENT_METADATA_HASH = keccak256("metadata:S1:deployment");
    bytes32 private constant DEPLOYMENT_ENVIRONMENT_HASH = keccak256("environment:documentation/runbooks");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("GOVPROV_DEV_DEPLOYER_PRIVATE_KEY");
        string memory manifestPath =
            vm.envOr("GOVPROV_DEPLOYMENT_MANIFEST", string("../runs/besu-dev/ledger/deployment_manifest.json"));
        string memory outputPath =
            vm.envOr("GOVPROV_S1_BESU_OUTPUT", string("../runs/besu-dev/scenarios/S1_runbook_update/govreplay_besu.json"));

        require(vm.addr(deployerPrivateKey) == GOVERNANCE_ADMIN, "private key must match governance admin");

        string memory manifest = vm.readFile(manifestPath);
        ActorRegistry actorRegistry =
            ActorRegistry(vm.parseJsonAddress(manifest, ".contracts.ActorRegistry.address"));
        PolicyRegistry policyRegistry =
            PolicyRegistry(vm.parseJsonAddress(manifest, ".contracts.PolicyRegistry.address"));
        ProvenanceRegistry provenanceRegistry =
            ProvenanceRegistry(vm.parseJsonAddress(manifest, ".contracts.ProvenanceRegistry.address"));
        ApprovalRegistry approvalRegistry =
            ApprovalRegistry(vm.parseJsonAddress(manifest, ".contracts.ApprovalRegistry.address"));
        DeploymentRegistry deploymentRegistry =
            DeploymentRegistry(vm.parseJsonAddress(manifest, ".contracts.DeploymentRegistry.address"));

        vm.startBroadcast(deployerPrivateKey);
        _ensureS1Actors(actorRegistry);
        _anchorS1Attestations(provenanceRegistry);
        _recordApproval(approvalRegistry);
        _recordDeployment(deploymentRegistry);
        vm.stopBroadcast();

        _requireReadback(policyRegistry, provenanceRegistry, approvalRegistry, deploymentRegistry);
        _writeOutput(
            outputPath,
            address(policyRegistry),
            address(provenanceRegistry),
            address(approvalRegistry),
            address(deploymentRegistry)
        );
    }

    function _ensureS1Actors(ActorRegistry actorRegistry) private {
        if (!actorRegistry.isRegisteredActor(RUNBOOK_AUTHOR)) {
            actorRegistry.registerActor(
                RUNBOOK_AUTHOR,
                keccak256("agent.runbook_author"),
                GovProvTypes.ActorType.AGENT,
                keccak256("metadata:agent.runbook_author")
            );
        }
        if (!actorRegistry.isRegisteredActor(POLICY_SERVICE)) {
            actorRegistry.registerActor(
                POLICY_SERVICE,
                keccak256("system.policy_service"),
                GovProvTypes.ActorType.SERVICE,
                keccak256("metadata:system.policy_service")
            );
        }
        if (!actorRegistry.isRegisteredActor(DOCUMENTATION_PUBLISHER)) {
            actorRegistry.registerActor(
                DOCUMENTATION_PUBLISHER,
                keccak256("service.documentation_publisher"),
                GovProvTypes.ActorType.SERVICE,
                keccak256("metadata:service.documentation_publisher")
            );
        }
        if (!actorRegistry.hasGovRole(GOVERNANCE_ADMIN, APPROVAL_ROLE)) {
            actorRegistry.grantGovRole(GOVERNANCE_ADMIN, APPROVAL_ROLE);
        }
        if (!actorRegistry.hasGovRole(RUNBOOK_AUTHOR, GovProvRoles.AGENT_ROLE)) {
            actorRegistry.grantGovRole(RUNBOOK_AUTHOR, GovProvRoles.AGENT_ROLE);
        }
        if (!actorRegistry.hasGovRole(POLICY_SERVICE, GovProvRoles.POLICY_EVALUATOR_ROLE)) {
            actorRegistry.grantGovRole(POLICY_SERVICE, GovProvRoles.POLICY_EVALUATOR_ROLE);
        }
        if (!actorRegistry.hasGovRole(DOCUMENTATION_PUBLISHER, GovProvRoles.DEPLOYER_ROLE)) {
            actorRegistry.grantGovRole(DOCUMENTATION_PUBLISHER, GovProvRoles.DEPLOYER_ROLE);
        }
    }

    function _anchorS1Attestations(ProvenanceRegistry provenanceRegistry) private {
        _anchorIfMissing(
            provenanceRegistry,
            OBSERVATION_HASH,
            provenanceRegistry.OBSERVATION_ATTESTATION(),
            OBSERVATION_SUBJECT_HASH,
            RUNBOOK_AUTHOR,
            bytes32(0),
            OBSERVATION_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            EVIDENCE_HASH,
            provenanceRegistry.EVIDENCE_BUNDLE_ATTESTATION(),
            EVIDENCE_SUBJECT_HASH,
            RUNBOOK_AUTHOR,
            OBSERVATION_HASH,
            EVIDENCE_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            POLICY_DECISION_HASH,
            provenanceRegistry.POLICY_DECISION_ATTESTATION(),
            POLICY_DECISION_SUBJECT_HASH,
            POLICY_SERVICE,
            EVIDENCE_HASH,
            POLICY_DECISION_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            ACTION_HASH,
            provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
            ACTION_SUBJECT_HASH,
            RUNBOOK_AUTHOR,
            _pairRoot(OBSERVATION_HASH, EVIDENCE_HASH),
            ACTION_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            APPROVAL_HASH,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            APPROVAL_SUBJECT_HASH,
            GOVERNANCE_ADMIN,
            ACTION_HASH,
            APPROVAL_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            ARTIFACT_HASH,
            provenanceRegistry.ARTIFACT_ATTESTATION(),
            ARTIFACT_SUBJECT_HASH,
            RUNBOOK_AUTHOR,
            APPROVAL_HASH,
            ARTIFACT_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            DEPLOYMENT_ATTESTATION_HASH,
            provenanceRegistry.DEPLOYMENT_ATTESTATION(),
            DEPLOYMENT_SUBJECT_HASH,
            DOCUMENTATION_PUBLISHER,
            _pairRoot(APPROVAL_HASH, ARTIFACT_HASH),
            DEPLOYMENT_METADATA_HASH
        );
    }

    function _anchorIfMissing(
        ProvenanceRegistry provenanceRegistry,
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor,
        bytes32 parentRoot,
        bytes32 metadataHash
    ) private {
        if (provenanceRegistry.attestationExists(attestationHash)) {
            return;
        }

        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            actor,
            DELIVERY_POLICY_V1,
            parentRoot,
            metadataHash,
            DEFAULT_SCOPE
        );
    }

    function _recordApproval(ApprovalRegistry approvalRegistry) private {
        if (approvalRegistry.approvalExists(APPROVAL_HASH)) {
            return;
        }

        approvalRegistry.recordApproval(
            ACTION_HASH,
            APPROVAL_HASH,
            ARTIFACT_HASH,
            POLICY_DECISION_HASH,
            RUNBOOK_AUTHOR,
            APPROVAL_ROLE,
            0
        );
    }

    function _recordDeployment(DeploymentRegistry deploymentRegistry) private {
        if (deploymentRegistry.deploymentExists(DEPLOYMENT_ID_HASH)) {
            return;
        }

        deploymentRegistry.recordDeployment(
            DEPLOYMENT_ID_HASH,
            DEPLOYMENT_ATTESTATION_HASH,
            ACTION_HASH,
            ARTIFACT_HASH,
            DELIVERY_POLICY_V1,
            APPROVAL_HASH,
            DEPLOYMENT_ENVIRONMENT_HASH
        );
    }

    function _requireReadback(
        PolicyRegistry policyRegistry,
        ProvenanceRegistry provenanceRegistry,
        ApprovalRegistry approvalRegistry,
        DeploymentRegistry deploymentRegistry
    ) private view {
        require(policyRegistry.getActivePolicy(DEFAULT_SCOPE) == DELIVERY_POLICY_V1, "active policy mismatch");
        require(provenanceRegistry.attestationExists(OBSERVATION_HASH), "observation anchor missing");
        require(provenanceRegistry.attestationExists(EVIDENCE_HASH), "evidence anchor missing");
        require(provenanceRegistry.attestationExists(POLICY_DECISION_HASH), "policy anchor missing");
        require(provenanceRegistry.attestationExists(ACTION_HASH), "action anchor missing");
        require(provenanceRegistry.attestationExists(APPROVAL_HASH), "approval anchor missing");
        require(provenanceRegistry.attestationExists(ARTIFACT_HASH), "artifact anchor missing");
        require(provenanceRegistry.attestationExists(DEPLOYMENT_ATTESTATION_HASH), "deployment anchor missing");
        require(approvalRegistry.isApprovalValid(APPROVAL_HASH), "approval readback invalid");
        require(deploymentRegistry.deploymentExists(DEPLOYMENT_ID_HASH), "deployment readback missing");
        require(
            deploymentRegistry.getDeploymentByAttestation(DEPLOYMENT_ATTESTATION_HASH) == DEPLOYMENT_ID_HASH,
            "deployment attestation lookup mismatch"
        );
    }

    function _writeOutput(
        string memory outputPath,
        address policyRegistryAddress,
        address provenanceRegistryAddress,
        address approvalRegistryAddress,
        address deploymentRegistryAddress
    ) private {
        string memory root = "s1";
        vm.serializeString(root, "schema_version", "govprov.s1_besu_run.v1");
        vm.serializeString(root, "scenario_id", "S1_runbook_update");
        vm.serializeString(root, "workflow_id", "wf-S1-P1-F0-0001");
        vm.serializeString(root, "mode", "govreplay_besu");
        vm.serializeUint(root, "chain_id", block.chainid);
        vm.serializeAddress(root, "policy_registry", policyRegistryAddress);
        vm.serializeAddress(root, "provenance_registry", provenanceRegistryAddress);
        vm.serializeAddress(root, "approval_registry", approvalRegistryAddress);
        vm.serializeAddress(root, "deployment_registry", deploymentRegistryAddress);
        vm.serializeBytes32(root, "active_policy_hash", DELIVERY_POLICY_V1);
        vm.serializeBytes32(root, "observation_attestation_hash", OBSERVATION_HASH);
        vm.serializeBytes32(root, "evidence_attestation_hash", EVIDENCE_HASH);
        vm.serializeBytes32(root, "policy_decision_attestation_hash", POLICY_DECISION_HASH);
        vm.serializeBytes32(root, "action_attestation_hash", ACTION_HASH);
        vm.serializeBytes32(root, "approval_attestation_hash", APPROVAL_HASH);
        vm.serializeBytes32(root, "artifact_attestation_hash", ARTIFACT_HASH);
        vm.serializeBytes32(root, "deployment_attestation_hash", DEPLOYMENT_ATTESTATION_HASH);
        vm.serializeBytes32(root, "deployment_id_hash", DEPLOYMENT_ID_HASH);
        vm.serializeBytes32(root, "approval_root", APPROVAL_HASH);
        vm.serializeBytes32(root, "environment_hash", DEPLOYMENT_ENVIRONMENT_HASH);
        vm.serializeString(root, "event_identifier_policy", "PolicyRegistry.PolicyActivated");
        vm.serializeString(root, "event_identifier_provenance", "ProvenanceRegistry.AttestationAnchored");
        vm.serializeString(root, "event_identifier_approval", "ApprovalRegistry.ApprovalRecorded");
        vm.serializeString(root, "event_identifier_deployment", "DeploymentRegistry.DeploymentRecorded");
        vm.serializeString(root, "transaction_trace_path", "contracts/broadcast/S1BesuScenario.s.sol/1337/run-latest.json");
        string memory finalJson = vm.serializeBool(root, "readback_ok", true);
        vm.writeJson(finalJson, outputPath);
    }

    function _pairRoot(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }
}
