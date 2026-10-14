// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract BesuLedgerSmoke is Script {
    address private constant GOVERNANCE_ADMIN = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
    address private constant DEPLOYER = 0xf17f52151EbEF6C7334FAD080c5704D77216b732;
    bytes32 private constant DEFAULT_SCOPE = keccak256("scope:default");
    bytes32 private constant DELIVERY_POLICY_V1 = keccak256("govprov:policy:delivery-v1");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("GOVPROV_DEV_DEPLOYER_PRIVATE_KEY");
        string memory manifestPath =
            vm.envOr("GOVPROV_DEPLOYMENT_MANIFEST", string("../runs/besu-dev/ledger/deployment_manifest.json"));
        string memory outputPath =
            vm.envOr("GOVPROV_LEDGER_SMOKE_OUTPUT", string("../runs/besu-dev/ledger/smoke.json"));
        string memory smokeLabel = vm.envOr("GOVPROV_LEDGER_SMOKE_LABEL", string("besu-dev"));

        require(vm.addr(deployerPrivateKey) == GOVERNANCE_ADMIN, "private key must match governance admin");

        string memory manifest = vm.readFile(manifestPath);
        address provenanceRegistryAddress =
            vm.parseJsonAddress(manifest, ".contracts.ProvenanceRegistry.address");
        address approvalRegistryAddress =
            vm.parseJsonAddress(manifest, ".contracts.ApprovalRegistry.address");
        address deploymentRegistryAddress =
            vm.parseJsonAddress(manifest, ".contracts.DeploymentRegistry.address");
        ProvenanceRegistry provenanceRegistry = ProvenanceRegistry(provenanceRegistryAddress);
        ApprovalRegistry approvalRegistry = ApprovalRegistry(approvalRegistryAddress);
        DeploymentRegistry deploymentRegistry = DeploymentRegistry(deploymentRegistryAddress);

        bytes32 actionHash =
            keccak256(abi.encodePacked("govprov:smoke:attestation:", smokeLabel, ":action-v1"));
        bytes32 approvalHash =
            keccak256(abi.encodePacked("govprov:smoke:attestation:", smokeLabel, ":approval-v1"));
        bytes32 deploymentAttestationHash =
            keccak256(abi.encodePacked("govprov:smoke:attestation:", smokeLabel, ":deployment-v1"));
        bytes32 artifactHash = keccak256(abi.encodePacked("govprov:smoke:artifact:", smokeLabel));
        bytes32 policyDecisionHash = keccak256(abi.encodePacked("govprov:smoke:policy-decision:", smokeLabel));
        bytes32 approvalRoot = keccak256(abi.encodePacked("govprov:smoke:approval-root:", smokeLabel));
        bytes32 deploymentIdHash = keccak256(abi.encodePacked("govprov:smoke:deployment:", smokeLabel));
        bytes32 environmentHash = keccak256(abi.encodePacked("govprov:smoke:environment:", smokeLabel));

        vm.startBroadcast(deployerPrivateKey);
        if (!provenanceRegistry.attestationExists(actionHash)) {
            _anchor(
                provenanceRegistry,
                actionHash,
                provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
                artifactHash,
                DEPLOYER,
                smokeLabel
            );
        }
        if (!provenanceRegistry.attestationExists(approvalHash)) {
            _anchor(
                provenanceRegistry,
                approvalHash,
                provenanceRegistry.APPROVAL_ATTESTATION(),
                artifactHash,
                GOVERNANCE_ADMIN,
                smokeLabel
            );
        }
        if (!provenanceRegistry.attestationExists(deploymentAttestationHash)) {
            _anchor(
                provenanceRegistry,
                deploymentAttestationHash,
                provenanceRegistry.DEPLOYMENT_ATTESTATION(),
                deploymentIdHash,
                DEPLOYER,
                smokeLabel
            );
        }
        if (!approvalRegistry.approvalExists(approvalHash)) {
            approvalRegistry.recordApproval(
                actionHash,
                approvalHash,
                artifactHash,
                policyDecisionHash,
                DEPLOYER,
                GovProvRoles.APPROVER_ROLE,
                0
            );
        }
        if (!deploymentRegistry.deploymentExists(deploymentIdHash)) {
            deploymentRegistry.recordDeployment(
                deploymentIdHash,
                deploymentAttestationHash,
                actionHash,
                artifactHash,
                DELIVERY_POLICY_V1,
                approvalRoot,
                environmentHash
            );
        }
        vm.stopBroadcast();

        GovProvTypes.AttestationRecord memory record =
            provenanceRegistry.getAttestation(deploymentAttestationHash);
        require(record.exists, "smoke attestation missing");
        require(record.attestationHash == deploymentAttestationHash, "attestation hash mismatch");
        require(record.subjectHash == deploymentIdHash, "subject hash mismatch");
        require(record.actor == DEPLOYER, "actor mismatch");
        require(record.policyHash == DELIVERY_POLICY_V1, "policy mismatch");
        require(approvalRegistry.isApprovalValid(approvalHash), "approval not valid");
        require(deploymentRegistry.deploymentExists(deploymentIdHash), "deployment missing");

        _writeSmokeOutput(
            outputPath,
            provenanceRegistryAddress,
            approvalRegistryAddress,
            deploymentRegistryAddress,
            actionHash,
            approvalHash,
            deploymentIdHash,
            record
        );
    }

    function _anchor(
        ProvenanceRegistry provenanceRegistry,
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor,
        string memory smokeLabel
    ) private {
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            actor,
            DELIVERY_POLICY_V1,
            keccak256(abi.encodePacked("govprov:smoke:parent-root:", smokeLabel, attestationHash)),
            keccak256(abi.encodePacked("govprov:smoke:metadata:", smokeLabel, attestationHash)),
            DEFAULT_SCOPE
        );
    }

    function _writeSmokeOutput(
        string memory outputPath,
        address provenanceRegistryAddress,
        address approvalRegistryAddress,
        address deploymentRegistryAddress,
        bytes32 actionHash,
        bytes32 approvalHash,
        bytes32 deploymentIdHash,
        GovProvTypes.AttestationRecord memory record
    ) private {
        string memory output = "smoke";
        vm.serializeString(output, "schema_version", "govprov.ledger-smoke.v1");
        vm.serializeString(output, "mode", "besu_live_smoke");
        vm.serializeUint(output, "chain_id", block.chainid);
        vm.serializeAddress(output, "provenance_registry", provenanceRegistryAddress);
        vm.serializeAddress(output, "approval_registry", approvalRegistryAddress);
        vm.serializeAddress(output, "deployment_registry", deploymentRegistryAddress);
        vm.serializeBytes32(output, "action_hash", actionHash);
        vm.serializeBytes32(output, "approval_hash", approvalHash);
        vm.serializeBytes32(output, "deployment_id_hash", deploymentIdHash);
        vm.serializeBytes32(output, "attestation_hash", record.attestationHash);
        vm.serializeBytes32(output, "attestation_type_hash", record.attestationTypeHash);
        vm.serializeBytes32(output, "subject_hash", record.subjectHash);
        vm.serializeAddress(output, "actor", record.actor);
        vm.serializeBytes32(output, "policy_hash", record.policyHash);
        vm.serializeBytes32(output, "parent_root", record.parentRoot);
        vm.serializeBytes32(output, "metadata_hash", record.metadataHash);
        vm.serializeBytes32(output, "scope_hash", record.scopeHash);
        vm.serializeUint(output, "anchored_at", record.anchoredAt);
        vm.serializeBool(output, "approval_recorded", true);
        vm.serializeBool(output, "deployment_recorded", true);
        string memory finalJson = vm.serializeBool(output, "readback_ok", true);
        vm.writeJson(finalJson, outputPath);
    }
}
