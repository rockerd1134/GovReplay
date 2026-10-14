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

contract S4BesuScenario is Script {
    address private constant GOVERNANCE_ADMIN = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
    address private constant DEPLOY_OPERATOR = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    address private constant POLICY_SERVICE = 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69;
    address private constant RELEASE_MANAGER = 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276;

    bytes32 private constant DEFAULT_SCOPE = keccak256("scope:default");
    bytes32 private constant DELIVERY_POLICY_V1 = keccak256("govprov:policy:delivery-v1");
    bytes32 private constant DELIVERY_POLICY_V3 = keccak256("govprov:policy:delivery-v3-evidence-strengthened");
    bytes32 private constant APPROVAL_ROLE = GovProvRoles.SECURITY_APPROVER_ROLE;

    bytes32 private constant OBSERVATION_HASH = 0xcae249d7efe4d8bdb809ec7dfd5c273a316399452fcf131b065fc8ab5c71bf95;
    bytes32 private constant EVIDENCE_HASH = 0xe206cb2cdb37e147c7a45f86cd39398cf6d763f93b6c569be814e36e3212dae4;
    bytes32 private constant POLICY_DECISION_HASH = 0x21a847ab36eda3bca1b0d37d7f222b6540433bcf7f51abf49903dcf56d5d58e4;
    bytes32 private constant ACTION_HASH = 0x078a429ff54b1cba6b8df520a52d564f1146f9d67f9db8d477afb415174a0162;
    bytes32 private constant APPROVAL_HASH = 0xa7fa0dc1ddb592c07de5ca698304abb52c51e9c6e6ce4210ae9017b29c3203ec;
    bytes32 private constant ARTIFACT_HASH = 0x5be069ab19367a00020745409b4a2c974260032f665b62852ddd8b82ce749c45;
    bytes32 private constant DEPLOYMENT_ATTESTATION_HASH = 0xbe93c1ceadc7120f36e5919e84c7658dd8fb1596d1573a1fb978c4d54ace6410;

    bytes32 private constant OBSERVATION_SUBJECT_HASH = 0xf1adcc4c98806b4a97d337b0c2962fd2980244ced86aa482126abd1cdddfd6ab;
    bytes32 private constant EVIDENCE_SUBJECT_HASH = 0x864380fffeb628500d39432750ff20542391a53b40d967132f06add601983fa4;
    bytes32 private constant POLICY_DECISION_SUBJECT_HASH = 0x641395c0704533da06c8960aea51d7b41e4135c4195f78d2557c932dd88335b7;
    bytes32 private constant ACTION_SUBJECT_HASH = 0x9042591817fb130e4f5d36d5076a0db6fafdc8ac759564b5a914ff883996a028;
    bytes32 private constant APPROVAL_SUBJECT_HASH = 0xa734d89695f9172baae9ee1ed5066be5453dedc635a195b0765202454421904a;
    bytes32 private constant ARTIFACT_SUBJECT_HASH = 0x7e46d5ee655c40ca2971ba1131f7709369fc97a17b4480bbbf29043366578d9c;
    bytes32 private constant DEPLOYMENT_SUBJECT_HASH = 0x68587236c1f7624a6df9ecba7fdd872482ede4d64d25631b27ebc6ba6b132b69;
    bytes32 private constant DEPLOYMENT_ID_HASH = keccak256("deployment-S4-0001:policy-gated-deployment");

    bytes32 private constant OBSERVATION_METADATA_HASH = keccak256("metadata:S4:observation");
    bytes32 private constant EVIDENCE_METADATA_HASH = keccak256("metadata:S4:evidence");
    bytes32 private constant POLICY_DECISION_METADATA_HASH = keccak256("metadata:S4:policy-decision");
    bytes32 private constant ACTION_METADATA_HASH = keccak256("metadata:S4:action");
    bytes32 private constant APPROVAL_METADATA_HASH = keccak256("metadata:S4:approval");
    bytes32 private constant ARTIFACT_METADATA_HASH = keccak256("metadata:S4:artifact");
    bytes32 private constant DEPLOYMENT_METADATA_HASH = keccak256("metadata:S4:deployment");
    bytes32 private constant DEPLOYMENT_ENVIRONMENT_HASH = keccak256("environment:staging/payment-api");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("GOVPROV_DEV_DEPLOYER_PRIVATE_KEY");
        string memory manifestPath =
            vm.envOr("GOVPROV_DEPLOYMENT_MANIFEST", string("../runs/besu-dev/ledger/deployment_manifest.json"));
        string memory outputPath = vm.envOr(
            "GOVPROV_S4_BESU_OUTPUT",
            string("../runs/besu-dev/scenarios/S4_policy_gated_deployment/govreplay_besu.json")
        );

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
        _ensureS4Actors(actorRegistry);
        _ensureS4Policy(policyRegistry);
        _anchorS4Attestations(provenanceRegistry);
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

    function _ensureS4Actors(ActorRegistry actorRegistry) private {
        if (!actorRegistry.isRegisteredActor(DEPLOY_OPERATOR)) {
            actorRegistry.registerActor(
                DEPLOY_OPERATOR,
                keccak256("agent.deploy_operator"),
                GovProvTypes.ActorType.AGENT,
                keccak256("metadata:agent.deploy_operator")
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
        if (!actorRegistry.isRegisteredActor(RELEASE_MANAGER)) {
            actorRegistry.registerActor(
                RELEASE_MANAGER,
                keccak256("human.release.drew"),
                GovProvTypes.ActorType.HUMAN,
                keccak256("metadata:human.release.drew")
            );
        }
        if (!actorRegistry.hasGovRole(GOVERNANCE_ADMIN, APPROVAL_ROLE)) {
            actorRegistry.grantGovRole(GOVERNANCE_ADMIN, APPROVAL_ROLE);
        }
        if (!actorRegistry.hasGovRole(DEPLOY_OPERATOR, GovProvRoles.AGENT_ROLE)) {
            actorRegistry.grantGovRole(DEPLOY_OPERATOR, GovProvRoles.AGENT_ROLE);
        }
        if (!actorRegistry.hasGovRole(DEPLOY_OPERATOR, GovProvRoles.DEPLOYER_ROLE)) {
            actorRegistry.grantGovRole(DEPLOY_OPERATOR, GovProvRoles.DEPLOYER_ROLE);
        }
        if (!actorRegistry.hasGovRole(POLICY_SERVICE, GovProvRoles.POLICY_EVALUATOR_ROLE)) {
            actorRegistry.grantGovRole(POLICY_SERVICE, GovProvRoles.POLICY_EVALUATOR_ROLE);
        }
        if (!actorRegistry.hasGovRole(RELEASE_MANAGER, APPROVAL_ROLE)) {
            actorRegistry.grantGovRole(RELEASE_MANAGER, APPROVAL_ROLE);
        }
    }

    function _ensureS4Policy(PolicyRegistry policyRegistry) private {
        if (!policyRegistry.policyExists(DELIVERY_POLICY_V3)) {
            policyRegistry.registerPolicy(
                DELIVERY_POLICY_V3,
                DELIVERY_POLICY_V1,
                keccak256("metadata:policy:P3:deployment"),
                DEFAULT_SCOPE
            );
        }
        if (policyRegistry.getActivePolicy(DEFAULT_SCOPE) != DELIVERY_POLICY_V3) {
            policyRegistry.activatePolicy(DELIVERY_POLICY_V3);
        }
    }

    function _anchorS4Attestations(ProvenanceRegistry provenanceRegistry) private {
        _anchorIfMissing(
            provenanceRegistry,
            OBSERVATION_HASH,
            provenanceRegistry.OBSERVATION_ATTESTATION(),
            OBSERVATION_SUBJECT_HASH,
            DEPLOY_OPERATOR,
            bytes32(0),
            OBSERVATION_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            EVIDENCE_HASH,
            provenanceRegistry.EVIDENCE_BUNDLE_ATTESTATION(),
            EVIDENCE_SUBJECT_HASH,
            DEPLOY_OPERATOR,
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
            DEPLOY_OPERATOR,
            _pairRoot(OBSERVATION_HASH, EVIDENCE_HASH),
            ACTION_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            APPROVAL_HASH,
            provenanceRegistry.APPROVAL_ATTESTATION(),
            APPROVAL_SUBJECT_HASH,
            RELEASE_MANAGER,
            ACTION_HASH,
            APPROVAL_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            ARTIFACT_HASH,
            provenanceRegistry.ARTIFACT_ATTESTATION(),
            ARTIFACT_SUBJECT_HASH,
            DEPLOY_OPERATOR,
            APPROVAL_HASH,
            ARTIFACT_METADATA_HASH
        );
        _anchorIfMissing(
            provenanceRegistry,
            DEPLOYMENT_ATTESTATION_HASH,
            provenanceRegistry.DEPLOYMENT_ATTESTATION(),
            DEPLOYMENT_SUBJECT_HASH,
            DEPLOY_OPERATOR,
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
            DELIVERY_POLICY_V3,
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
            DEPLOY_OPERATOR,
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
            DELIVERY_POLICY_V3,
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
        require(policyRegistry.getActivePolicy(DEFAULT_SCOPE) == DELIVERY_POLICY_V3, "active policy mismatch");
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
        string memory root = "s4";
        vm.serializeString(root, "schema_version", "govprov.s4_besu_run.v1");
        vm.serializeString(root, "scenario_id", "S4_policy_gated_deployment");
        vm.serializeString(root, "workflow_id", "wf-S4-P3-F0-0001");
        vm.serializeString(root, "mode", "govreplay_besu");
        vm.serializeUint(root, "chain_id", block.chainid);
        vm.serializeAddress(root, "policy_registry", policyRegistryAddress);
        vm.serializeAddress(root, "provenance_registry", provenanceRegistryAddress);
        vm.serializeAddress(root, "approval_registry", approvalRegistryAddress);
        vm.serializeAddress(root, "deployment_registry", deploymentRegistryAddress);
        vm.serializeBytes32(root, "active_policy_hash", DELIVERY_POLICY_V3);
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
        vm.serializeString(root, "deployment_id", "deployment-S4-0001");
        vm.serializeString(root, "event_identifier_policy", "PolicyRegistry.PolicyActivated");
        vm.serializeString(root, "event_identifier_provenance", "ProvenanceRegistry.AttestationAnchored");
        vm.serializeString(root, "event_identifier_approval", "ApprovalRegistry.ApprovalRecorded");
        vm.serializeString(root, "event_identifier_deployment", "DeploymentRegistry.DeploymentRecorded");
        vm.serializeString(root, "transaction_trace_path", "contracts/broadcast/S4BesuScenario.s.sol/1337/run-latest.json");
        string memory finalJson = vm.serializeBool(root, "readback_ok", true);
        vm.writeJson(finalJson, outputPath);
    }

    function _pairRoot(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }
}

