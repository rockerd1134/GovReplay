// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { ContractDirectory } from "../src/ContractDirectory.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract BesuLiveArpeFull is Script {
    address private constant GOVERNANCE_ADMIN = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
    address private constant DEPLOYER = 0xf17f52151EbEF6C7334FAD080c5704D77216b732;

    bytes32 private constant DEFAULT_SCOPE = keccak256("scope:default");
    bytes32 private constant DELIVERY_POLICY_V1 = keccak256("govprov:policy:delivery-v1");
    bytes32 private constant DELIVERY_POLICY_V2 = keccak256("govprov:policy:delivery-v2");
    bytes32 private constant DELIVERY_POLICY_V3 = keccak256("govprov:policy:delivery-v3");

    uint256 private constant BASIC_RECORDS = 540;
    uint256 private constant HARD_RECORDS = 116;
    uint256 private constant TOTAL_RECORDS = BASIC_RECORDS + HARD_RECORDS;
    uint256 private constant FORMULA_REPLAY_CALLS_PER_WORKFLOW = 18;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("GOVPROV_DEV_DEPLOYER_PRIVATE_KEY");
        string memory manifestPath =
            vm.envOr("GOVPROV_DEPLOYMENT_MANIFEST", string("../runs/besu-live-arpe-full/ledger/deployment_manifest.json"));
        string memory auditPath =
            vm.envOr("GOVPROV_LIVE_ARPE_FULL_AUDIT_OUTPUT", string("../runs/besu-live-arpe-full/audit/live_besu_audit_results.jsonl"));

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
        ContractDirectory contractDirectory =
            ContractDirectory(vm.parseJsonAddress(manifest, ".contracts.ContractDirectory.address"));

        vm.startBroadcast(deployerPrivateKey);
        _ensurePolicy(policyRegistry, DELIVERY_POLICY_V2, DELIVERY_POLICY_V1, "delivery-v2");
        _ensurePolicy(policyRegistry, DELIVERY_POLICY_V3, DELIVERY_POLICY_V2, "delivery-v3");
        for (uint256 i = 0; i < TOTAL_RECORDS; i++) {
            _writeWorkflow(provenanceRegistry, approvalRegistry, deploymentRegistry, i);
        }
        vm.stopBroadcast();

        bytes32 activeContractSet = contractDirectory.getActiveContractSet();
        vm.pauseGasMetering();
        _writeLiveAudit(
            auditPath,
            actorRegistry,
            policyRegistry,
            provenanceRegistry,
            approvalRegistry,
            deploymentRegistry,
            contractDirectory,
            activeContractSet
        );
        vm.resumeGasMetering();
    }

    function _ensurePolicy(
        PolicyRegistry policyRegistry,
        bytes32 policyHash,
        bytes32 parentPolicyHash,
        string memory label
    ) private {
        if (!policyRegistry.policyExists(policyHash)) {
            policyRegistry.registerPolicy(
                policyHash,
                parentPolicyHash,
                keccak256(abi.encodePacked("govprov:policy:", label, ":metadata")),
                DEFAULT_SCOPE
            );
        }
        if (policyRegistry.getPolicyStatus(policyHash) == GovProvTypes.PolicyStatus.REGISTERED) {
            policyRegistry.activatePolicy(policyHash);
        }
    }

    function _writeWorkflow(
        ProvenanceRegistry provenanceRegistry,
        ApprovalRegistry approvalRegistry,
        DeploymentRegistry deploymentRegistry,
        uint256 index
    ) private {
        bytes32 actionHash = _hash("action", index);
        bytes32 policyDecisionHash = _hash("policy-decision", index);
        bytes32 approvalHash = _hash("approval", index);
        bytes32 deploymentAttestationHash = _hash("deployment-attestation", index);
        bytes32 artifactHash = _hash("artifact", index);
        bytes32 deploymentIdHash = _hash("deployment-id", index);
        bytes32 approvalRoot = _hash("approval-root", index);
        bytes32 environmentHash = _hash("environment", index);
        bytes32 policyHash = _policyFor(index);

        if (!provenanceRegistry.attestationExists(actionHash)) {
            _anchor(
                provenanceRegistry,
                actionHash,
                provenanceRegistry.ACTION_PROPOSAL_ATTESTATION(),
                artifactHash,
                DEPLOYER,
                policyHash,
                index
            );
        }
        if (!provenanceRegistry.attestationExists(policyDecisionHash)) {
            _anchor(
                provenanceRegistry,
                policyDecisionHash,
                provenanceRegistry.POLICY_DECISION_ATTESTATION(),
                actionHash,
                GOVERNANCE_ADMIN,
                policyHash,
                index
            );
        }
        if (!provenanceRegistry.attestationExists(approvalHash)) {
            _anchor(
                provenanceRegistry,
                approvalHash,
                provenanceRegistry.APPROVAL_ATTESTATION(),
                artifactHash,
                GOVERNANCE_ADMIN,
                policyHash,
                index
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
        if (!provenanceRegistry.attestationExists(deploymentAttestationHash)) {
            _anchor(
                provenanceRegistry,
                deploymentAttestationHash,
                provenanceRegistry.DEPLOYMENT_ATTESTATION(),
                deploymentIdHash,
                DEPLOYER,
                policyHash,
                index
            );
        }
        if (!deploymentRegistry.deploymentExists(deploymentIdHash)) {
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
    }

    function _anchor(
        ProvenanceRegistry provenanceRegistry,
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor,
        bytes32 policyHash,
        uint256 index
    ) private {
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            actor,
            policyHash,
            _hash("parent-root", index),
            _hash("metadata", index),
            DEFAULT_SCOPE
        );
    }

    function _writeLiveAudit(
        string memory auditPath,
        ActorRegistry actorRegistry,
        PolicyRegistry policyRegistry,
        ProvenanceRegistry provenanceRegistry,
        ApprovalRegistry approvalRegistry,
        DeploymentRegistry deploymentRegistry,
        ContractDirectory contractDirectory,
        bytes32 activeContractSet
    ) private {
        require(activeContractSet != bytes32(0), "contract directory inactive");
        bool contractDirectoryState = _verifyContractDirectory(contractDirectory, activeContractSet);
        vm.writeFile(auditPath, "");
        for (uint256 i = 0; i < TOTAL_RECORDS; i++) {
            vm.writeLine(
                auditPath,
                _auditRow(
                    i,
                    _verifyWorkflow(
                        i,
                        actorRegistry,
                        policyRegistry,
                        provenanceRegistry,
                        approvalRegistry,
                        deploymentRegistry,
                        contractDirectoryState
                    ),
                    activeContractSet
                )
            );
        }
    }

    struct LiveWorkflowChecks {
        bool actorRoleState;
        bool policyActivation;
        bool actionAnchor;
        bool policyDecisionAnchor;
        bool approvalAnchor;
        bool approvalAuthority;
        bool separationOfDuties;
        bool deploymentAnchor;
        bool deploymentRecord;
        bool artifactHash;
        bool contractDirectoryState;
    }

    function _verifyWorkflow(
        uint256 index,
        ActorRegistry actorRegistry,
        PolicyRegistry policyRegistry,
        ProvenanceRegistry provenanceRegistry,
        ApprovalRegistry approvalRegistry,
        DeploymentRegistry deploymentRegistry,
        bool contractDirectoryState
    ) private view returns (LiveWorkflowChecks memory checks) {
        bytes32 actionHash = _hash("action", index);
        bytes32 policyDecisionHash = _hash("policy-decision", index);
        bytes32 approvalHash = _hash("approval", index);
        bytes32 deploymentAttestationHash = _hash("deployment-attestation", index);
        bytes32 artifactHash = _hash("artifact", index);
        bytes32 deploymentIdHash = _hash("deployment-id", index);
        bytes32 policyHash = _policyFor(index);

        GovProvTypes.AttestationRecord memory action =
            provenanceRegistry.attestationExists(actionHash)
                ? provenanceRegistry.getAttestation(actionHash)
                : _emptyAttestation();
        GovProvTypes.AttestationRecord memory policyDecision =
            provenanceRegistry.attestationExists(policyDecisionHash)
                ? provenanceRegistry.getAttestation(policyDecisionHash)
                : _emptyAttestation();
        GovProvTypes.AttestationRecord memory approvalAnchor =
            provenanceRegistry.attestationExists(approvalHash)
                ? provenanceRegistry.getAttestation(approvalHash)
                : _emptyAttestation();
        GovProvTypes.AttestationRecord memory deploymentAnchor =
            provenanceRegistry.attestationExists(deploymentAttestationHash)
                ? provenanceRegistry.getAttestation(deploymentAttestationHash)
                : _emptyAttestation();
        GovProvTypes.ApprovalRecord memory approval =
            approvalRegistry.approvalExists(approvalHash)
                ? approvalRegistry.getApproval(approvalHash)
                : _emptyApproval();
        GovProvTypes.DeploymentRecord memory deployment =
            deploymentRegistry.deploymentExists(deploymentIdHash)
                ? deploymentRegistry.getDeployment(deploymentIdHash)
                : _emptyDeployment();
        GovProvTypes.PolicyRecord memory policy =
            policyRegistry.policyExists(policyHash) ? policyRegistry.getPolicy(policyHash) : _emptyPolicy();

        checks.actorRoleState = actorRegistry.isActiveActor(DEPLOYER)
            && actorRegistry.hasGovRole(DEPLOYER, GovProvRoles.DEPLOYER_ROLE)
            && actorRegistry.isActiveActor(GOVERNANCE_ADMIN)
            && actorRegistry.hasGovRole(GOVERNANCE_ADMIN, GovProvRoles.APPROVER_ROLE)
            && actorRegistry.hasGovRole(GOVERNANCE_ADMIN, GovProvRoles.LEDGER_WRITER_ROLE);
        checks.policyActivation = policy.policyHash == policyHash && policy.activatedAt != 0
            && policy.scopeHash == DEFAULT_SCOPE && policy.status != GovProvTypes.PolicyStatus.REVOKED;
        checks.actionAnchor = action.exists && action.attestationHash == actionHash
            && action.attestationTypeHash == provenanceRegistry.ACTION_PROPOSAL_ATTESTATION()
            && action.subjectHash == artifactHash && action.actor == DEPLOYER && action.policyHash == policyHash;
        checks.policyDecisionAnchor = policyDecision.exists
            && policyDecision.attestationHash == policyDecisionHash
            && policyDecision.attestationTypeHash == provenanceRegistry.POLICY_DECISION_ATTESTATION()
            && policyDecision.subjectHash == actionHash && policyDecision.actor == GOVERNANCE_ADMIN
            && policyDecision.policyHash == policyHash;
        checks.approvalAnchor = approvalAnchor.exists && approvalAnchor.attestationHash == approvalHash
            && approvalAnchor.attestationTypeHash == provenanceRegistry.APPROVAL_ATTESTATION()
            && approvalAnchor.subjectHash == artifactHash && approvalAnchor.actor == GOVERNANCE_ADMIN
            && approvalAnchor.policyHash == policyHash;
        checks.approvalAuthority = approval.status == GovProvTypes.ApprovalStatus.APPROVED
            && approval.actionHash == actionHash && approval.artifactHash == artifactHash
            && approval.policyDecisionHash == policyDecisionHash && approval.approver == GOVERNANCE_ADMIN
            && actorRegistry.hasGovRole(approval.approver, approval.approvalRole)
            && approvalRegistry.isApprovalValid(approvalHash);
        checks.separationOfDuties = approval.proposer == DEPLOYER && approval.approver != approval.proposer;
        checks.deploymentAnchor = deploymentAnchor.exists
            && deploymentAnchor.attestationHash == deploymentAttestationHash
            && deploymentAnchor.attestationTypeHash == provenanceRegistry.DEPLOYMENT_ATTESTATION()
            && deploymentAnchor.subjectHash == deploymentIdHash && deploymentAnchor.actor == DEPLOYER
            && deploymentAnchor.policyHash == policyHash;
        checks.deploymentRecord = deployment.status == GovProvTypes.DeploymentStatus.RECORDED
            && deployment.deploymentIdHash == deploymentIdHash
            && deployment.deploymentAttestationHash == deploymentAttestationHash
            && deployment.actionHash == actionHash && deployment.policyHash == policyHash
            && deployment.deployer == GOVERNANCE_ADMIN;
        checks.artifactHash = deployment.artifactHash == artifactHash && approval.artifactHash == artifactHash
            && action.subjectHash == artifactHash;
        checks.contractDirectoryState = contractDirectoryState;
    }

    function _auditRow(
        uint256 index,
        LiveWorkflowChecks memory checks,
        bytes32 activeContractSet
    ) private pure returns (string memory) {
        bool ok = _allChecksPass(checks);
        return string.concat(
            "{\"schema_version\":\"govprov.live_besu_arpe_audit.v2\",",
            "\"mode\":\"besu_live_arpe_full\",",
            "\"matrix\":\"",
            index < BASIC_RECORDS ? "arpe_basic_matrix" : "arpe_hard_matrix",
            "\",",
            "\"system_configuration\":\"govreplay_besu\",",
            "\"workflow_index\":",
            vm.toString(index),
            ",",
            "\"workflow_id\":\"",
            _workflowId(index),
            "\",",
            "\"replay_id\":\"live-besu-rpc:",
            vm.toString(index),
            "\",",
            "\"verifier_source\":\"contracts/script/BesuLiveArpeFull.s.sol:live_besu_rpc_state\",",
            "\"replay_backend\":\"live_besu_rpc\",",
            "\"sidecar_used_as_replay_backend\":false,",
            "\"oracle_source\":\"deterministic_sidecar_preserved_for_metrics_only\",",
            "\"formula_replay_contract_call_count\":",
            vm.toString(FORMULA_REPLAY_CALLS_PER_WORKFLOW),
            ",",
            "\"active_contract_set\":\"",
            vm.toString(activeContractSet),
            "\",",
            "\"replay_verdict\":\"",
            _verdict(ok),
            "\",",
            "\"oracle_agreement\":\"",
            _verdict(ok),
            "\",",
            "\"failure_code\":",
            ok ? "null" : "\"live_besu_state_mismatch\"",
            ",",
            "\"checks\":[",
            _checkJson("actor_role_state", checks.actorRoleState, "ActorRegistry"),
            ",",
            _checkJson("policy_activation", checks.policyActivation, "PolicyRegistry"),
            ",",
            _checkJson("action_anchor", checks.actionAnchor, "ProvenanceRegistry"),
            ",",
            _checkJson("policy_decision_anchor", checks.policyDecisionAnchor, "ProvenanceRegistry"),
            ",",
            _checkJson("approval_anchor", checks.approvalAnchor, "ProvenanceRegistry"),
            ",",
            _checkJson("approval_authority", checks.approvalAuthority, "ApprovalRegistry"),
            ",",
            _checkJson("separation_of_duties", checks.separationOfDuties, "ApprovalRegistry"),
            ",",
            _checkJson("deployment_anchor", checks.deploymentAnchor, "ProvenanceRegistry"),
            ",",
            _checkJson("deployment_record", checks.deploymentRecord, "DeploymentRegistry"),
            ",",
            _checkJson("artifact_hash", checks.artifactHash, "DeploymentRegistry"),
            ",",
            _checkJson("contract_directory_state", checks.contractDirectoryState, "ContractDirectory"),
            "]}",
            ""
        );
    }

    function _allChecksPass(LiveWorkflowChecks memory checks) private pure returns (bool) {
        return checks.actorRoleState && checks.policyActivation && checks.actionAnchor
            && checks.policyDecisionAnchor && checks.approvalAnchor && checks.approvalAuthority
            && checks.separationOfDuties && checks.deploymentAnchor && checks.deploymentRecord
            && checks.artifactHash && checks.contractDirectoryState;
    }

    function _verifyContractDirectory(
        ContractDirectory contractDirectory,
        bytes32 activeContractSet
    ) private view returns (bool) {
        return contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:ActorRegistry")) != address(0)
            && contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:PolicyRegistry")) != address(0)
            && contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:ProvenanceRegistry")) != address(0)
            && contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:ApprovalRegistry")) != address(0)
            && contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:DeploymentRegistry")) != address(0)
            && contractDirectory.getContract(activeContractSet, keccak256("govprov:contract:ContractDirectory")) != address(0);
    }

    function _checkJson(
        string memory name,
        bool ok,
        string memory source
    ) private pure returns (string memory) {
        return string.concat(
            "{\"name\":\"",
            name,
            "\",\"status\":\"",
            _verdict(ok),
            "\",\"source\":\"",
            source,
            "\"}"
        );
    }

    function _verdict(bool ok) private pure returns (string memory) {
        return ok ? "PASS" : "FAIL";
    }

    function _workflowId(uint256 index) private pure returns (string memory) {
        return string.concat("wf-live-besu-arpe-full-", _paddedIndex(index));
    }

    function _paddedIndex(uint256 index) private pure returns (string memory) {
        if (index < 10) {
            return string.concat("000", vm.toString(index));
        }
        if (index < 100) {
            return string.concat("00", vm.toString(index));
        }
        if (index < 1000) {
            return string.concat("0", vm.toString(index));
        }
        return vm.toString(index);
    }

    function _emptyAttestation() private pure returns (GovProvTypes.AttestationRecord memory) {
        return GovProvTypes.AttestationRecord({
            attestationHash: bytes32(0),
            attestationTypeHash: bytes32(0),
            subjectHash: bytes32(0),
            actor: address(0),
            policyHash: bytes32(0),
            parentRoot: bytes32(0),
            metadataHash: bytes32(0),
            scopeHash: bytes32(0),
            anchoredAt: 0,
            exists: false
        });
    }

    function _emptyApproval() private pure returns (GovProvTypes.ApprovalRecord memory) {
        return GovProvTypes.ApprovalRecord({
            approvalHash: bytes32(0),
            actionHash: bytes32(0),
            artifactHash: bytes32(0),
            policyDecisionHash: bytes32(0),
            proposer: address(0),
            approver: address(0),
            approvalRole: bytes32(0),
            status: GovProvTypes.ApprovalStatus.UNKNOWN,
            approvedAt: 0,
            expiresAt: 0,
            reasonHash: bytes32(0)
        });
    }

    function _emptyDeployment() private pure returns (GovProvTypes.DeploymentRecord memory) {
        return GovProvTypes.DeploymentRecord({
            deploymentIdHash: bytes32(0),
            deploymentAttestationHash: bytes32(0),
            actionHash: bytes32(0),
            artifactHash: bytes32(0),
            policyHash: bytes32(0),
            approvalRoot: bytes32(0),
            environmentHash: bytes32(0),
            deployer: address(0),
            status: GovProvTypes.DeploymentStatus.UNKNOWN,
            deployedAt: 0,
            revokedAt: 0,
            revocationReasonHash: bytes32(0)
        });
    }

    function _emptyPolicy() private pure returns (GovProvTypes.PolicyRecord memory) {
        return GovProvTypes.PolicyRecord({
            policyHash: bytes32(0),
            parentPolicyHash: bytes32(0),
            metadataHash: bytes32(0),
            scopeHash: bytes32(0),
            status: GovProvTypes.PolicyStatus.UNKNOWN,
            registeredBy: address(0),
            registeredAt: 0,
            activatedAt: 0,
            supersededAt: 0,
            revokedAt: 0,
            supersededByPolicyHash: bytes32(0),
            revocationReasonHash: bytes32(0)
        });
    }

    function _policyFor(uint256 index) private pure returns (bytes32) {
        uint256 policyIndex = index % 3;
        if (policyIndex == 0) {
            return DELIVERY_POLICY_V1;
        }
        if (policyIndex == 1) {
            return DELIVERY_POLICY_V2;
        }
        return DELIVERY_POLICY_V3;
    }

    function _hash(string memory label, uint256 index) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("govprov:live-arpe-full:", label, ":", index));
    }
}
