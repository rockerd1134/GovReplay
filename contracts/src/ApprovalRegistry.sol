// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { ProvenanceRegistry } from "./ProvenanceRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract ApprovalRegistry {
    ActorRegistry public immutable actorRegistry;
    ProvenanceRegistry public immutable provenanceRegistry;

    mapping(bytes32 approvalHash => GovProvTypes.ApprovalRecord record) private _approvals;
    mapping(bytes32 actionHash => bytes32[] approvalHashes) private _approvalsByAction;

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

    constructor(ActorRegistry actorRegistry_, ProvenanceRegistry provenanceRegistry_) {
        GovProvValidation.requireNonZeroAddress(address(actorRegistry_));
        GovProvValidation.requireNonZeroAddress(address(provenanceRegistry_));
        actorRegistry = actorRegistry_;
        provenanceRegistry = provenanceRegistry_;
    }

    function recordApproval(
        bytes32 actionHash,
        bytes32 approvalHash,
        bytes32 artifactHash,
        bytes32 policyDecisionHash,
        address proposer,
        bytes32 approvalRole,
        uint64 expiresAt
    ) external {
        _requireApprovalInputs(
            actionHash, approvalHash, artifactHash, policyDecisionHash, proposer, approvalRole
        );

        _approvals[approvalHash] = GovProvTypes.ApprovalRecord({
            approvalHash: approvalHash,
            actionHash: actionHash,
            artifactHash: artifactHash,
            policyDecisionHash: policyDecisionHash,
            proposer: proposer,
            approver: msg.sender,
            approvalRole: approvalRole,
            status: GovProvTypes.ApprovalStatus.APPROVED,
            approvedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            reasonHash: bytes32(0)
        });
        _approvalsByAction[actionHash].push(approvalHash);

        emit ApprovalRecorded(
            actionHash,
            approvalHash,
            msg.sender,
            approvalRole,
            artifactHash,
            policyDecisionHash,
            proposer,
            expiresAt
        );
    }

    function recordRejection(
        bytes32 actionHash,
        bytes32 approvalHash,
        bytes32 artifactHash,
        bytes32 policyDecisionHash,
        address proposer,
        bytes32 approvalRole,
        bytes32 reasonHash
    ) external {
        _requireApprovalInputs(
            actionHash, approvalHash, artifactHash, policyDecisionHash, proposer, approvalRole
        );
        GovProvValidation.requireNonZeroHash(reasonHash, "reasonHash");

        _approvals[approvalHash] = GovProvTypes.ApprovalRecord({
            approvalHash: approvalHash,
            actionHash: actionHash,
            artifactHash: artifactHash,
            policyDecisionHash: policyDecisionHash,
            proposer: proposer,
            approver: msg.sender,
            approvalRole: approvalRole,
            status: GovProvTypes.ApprovalStatus.REJECTED,
            approvedAt: uint64(block.timestamp),
            expiresAt: 0,
            reasonHash: reasonHash
        });
        _approvalsByAction[actionHash].push(approvalHash);

        emit ApprovalRejected(actionHash, approvalHash, msg.sender, approvalRole, reasonHash);
    }

    function revokeApproval(bytes32 approvalHash, bytes32 reasonHash) external {
        GovProvTypes.ApprovalRecord storage approval = _requireApproval(approvalHash);
        _requireActiveActor(msg.sender);

        bool isOriginalApprover = msg.sender == approval.approver;
        bool isGovernanceAdmin =
            actorRegistry.hasGovRole(msg.sender, GovProvRoles.GOVERNANCE_ADMIN_ROLE);
        if (!isOriginalApprover && !isGovernanceAdmin) {
            revert GovProvErrors.MissingRole(msg.sender, GovProvRoles.GOVERNANCE_ADMIN_ROLE);
        }
        if (approval.status != GovProvTypes.ApprovalStatus.APPROVED) {
            revert GovProvErrors.ApprovalNotValid(approvalHash);
        }

        approval.status = GovProvTypes.ApprovalStatus.REVOKED;
        approval.reasonHash = reasonHash;

        emit ApprovalRevoked(approvalHash, approval.approver, reasonHash, msg.sender);
    }

    function approvalExists(bytes32 approvalHash) public view returns (bool) {
        return _approvals[approvalHash].status != GovProvTypes.ApprovalStatus.UNKNOWN;
    }

    function getApproval(bytes32 approvalHash)
        external
        view
        returns (GovProvTypes.ApprovalRecord memory)
    {
        return _requireApprovalView(approvalHash);
    }

    function isApprovalValid(bytes32 approvalHash) public view returns (bool) {
        if (!approvalExists(approvalHash)) {
            return false;
        }

        GovProvTypes.ApprovalRecord storage approval = _approvals[approvalHash];
        if (approval.status != GovProvTypes.ApprovalStatus.APPROVED) {
            return false;
        }
        if (approval.expiresAt != 0 && block.timestamp > approval.expiresAt) {
            return false;
        }

        return actorRegistry.isActiveActor(approval.approver);
    }

    function hasValidApprovalForArtifact(bytes32 actionHash, bytes32 artifactHash, bytes32 role)
        external
        view
        returns (bool)
    {
        bytes32[] storage approvalHashes = _approvalsByAction[actionHash];
        for (uint256 i = 0; i < approvalHashes.length; i++) {
            GovProvTypes.ApprovalRecord storage approval = _approvals[approvalHashes[i]];
            if (
                approval.artifactHash == artifactHash && approval.approvalRole == role
                    && isApprovalValid(approval.approvalHash)
            ) {
                return true;
            }
        }

        return false;
    }

    function getApprovalCount(bytes32 actionHash) external view returns (uint256) {
        return _approvalsByAction[actionHash].length;
    }

    function getApprovalByActionAt(bytes32 actionHash, uint256 index)
        external
        view
        returns (bytes32)
    {
        return _approvalsByAction[actionHash][index];
    }

    function _requireApprovalInputs(
        bytes32 actionHash,
        bytes32 approvalHash,
        bytes32 artifactHash,
        bytes32 policyDecisionHash,
        address proposer,
        bytes32 approvalRole
    ) private view {
        _requireActiveActor(msg.sender);
        _requireAllowedApprovalRole(approvalRole);
        if (!actorRegistry.hasGovRole(msg.sender, approvalRole)) {
            revert GovProvErrors.MissingRole(msg.sender, approvalRole);
        }
        GovProvValidation.requireNonZeroHash(actionHash, "actionHash");
        GovProvValidation.requireNonZeroHash(approvalHash, "approvalHash");
        GovProvValidation.requireNonZeroHash(artifactHash, "artifactHash");
        GovProvValidation.requireNonZeroHash(policyDecisionHash, "policyDecisionHash");
        GovProvValidation.requireNonZeroAddress(proposer);
        _requireRegisteredProposer(proposer);
        if (msg.sender == proposer) {
            revert GovProvErrors.SeparationOfDutiesViolation(proposer, msg.sender);
        }
        if (!provenanceRegistry.attestationExists(actionHash)) {
            revert GovProvErrors.AttestationNotFound(actionHash);
        }
        if (!provenanceRegistry.attestationExists(approvalHash)) {
            revert GovProvErrors.AttestationNotFound(approvalHash);
        }
        if (approvalExists(approvalHash)) {
            revert GovProvErrors.ApprovalAlreadyRecorded(approvalHash);
        }
    }

    function _requireAllowedApprovalRole(bytes32 approvalRole) private pure {
        if (
            approvalRole != GovProvRoles.APPROVER_ROLE
                && approvalRole != GovProvRoles.SECURITY_APPROVER_ROLE
        ) {
            revert GovProvErrors.InvalidStatusTransition();
        }
    }

    function _requireApproval(bytes32 approvalHash)
        private
        view
        returns (GovProvTypes.ApprovalRecord storage)
    {
        if (!approvalExists(approvalHash)) {
            revert GovProvErrors.ApprovalNotFound(approvalHash);
        }
        return _approvals[approvalHash];
    }

    function _requireApprovalView(bytes32 approvalHash)
        private
        view
        returns (GovProvTypes.ApprovalRecord storage)
    {
        if (!approvalExists(approvalHash)) {
            revert GovProvErrors.ApprovalNotFound(approvalHash);
        }
        return _approvals[approvalHash];
    }

    function _requireActiveActor(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
    }

    function _requireRegisteredProposer(address proposer) private view {
        if (!actorRegistry.isRegisteredActor(proposer)) {
            revert GovProvErrors.ActorNotRegistered(proposer);
        }
    }
}
