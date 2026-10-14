// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

library GovProvTypes {
    enum ActorType {
        UNKNOWN,
        HUMAN,
        AGENT,
        SERVICE,
        CONTRACT
    }

    enum ActorStatus {
        UNKNOWN,
        ACTIVE,
        SUSPENDED,
        REVOKED
    }

    enum PolicyStatus {
        UNKNOWN,
        REGISTERED,
        ACTIVE,
        SUPERSEDED,
        REVOKED
    }

    enum ApprovalStatus {
        UNKNOWN,
        APPROVED,
        REJECTED,
        REVOKED,
        EXPIRED
    }

    enum DeploymentStatus {
        UNKNOWN,
        RECORDED,
        SUPERSEDED,
        REVOKED
    }

    enum ContractStatus {
        UNKNOWN,
        REGISTERED,
        ACTIVE,
        SUPERSEDED,
        REVOKED
    }

    struct ActorRecord {
        address actor;
        bytes32 actorIdHash;
        bytes32 metadataHash;
        ActorType actorType;
        ActorStatus status;
        uint64 registeredAt;
        uint64 suspendedAt;
        uint64 revokedAt;
        bytes32 revocationReasonHash;
    }

    struct PolicyRecord {
        bytes32 policyHash;
        bytes32 parentPolicyHash;
        bytes32 metadataHash;
        bytes32 scopeHash;
        PolicyStatus status;
        address registeredBy;
        uint64 registeredAt;
        uint64 activatedAt;
        uint64 supersededAt;
        uint64 revokedAt;
        bytes32 supersededByPolicyHash;
        bytes32 revocationReasonHash;
    }

    struct AttestationRecord {
        bytes32 attestationHash;
        bytes32 attestationTypeHash;
        bytes32 subjectHash;
        address actor;
        bytes32 policyHash;
        bytes32 parentRoot;
        bytes32 metadataHash;
        bytes32 scopeHash;
        uint64 anchoredAt;
        bool exists;
    }

    struct ApprovalRecord {
        bytes32 approvalHash;
        bytes32 actionHash;
        bytes32 artifactHash;
        bytes32 policyDecisionHash;
        address proposer;
        address approver;
        bytes32 approvalRole;
        ApprovalStatus status;
        uint64 approvedAt;
        uint64 expiresAt;
        bytes32 reasonHash;
    }

    struct DeploymentRecord {
        bytes32 deploymentIdHash;
        bytes32 deploymentAttestationHash;
        bytes32 actionHash;
        bytes32 artifactHash;
        bytes32 policyHash;
        bytes32 approvalRoot;
        bytes32 environmentHash;
        address deployer;
        DeploymentStatus status;
        uint64 deployedAt;
        uint64 revokedAt;
        bytes32 revocationReasonHash;
    }

    struct ContractRecord {
        bytes32 nameHash;
        address contractAddress;
        bytes32 versionHash;
        bytes32 sourceHash;
        bytes32 abiHash;
        bytes32 metadataHash;
        ContractStatus status;
        address registeredBy;
        uint64 registeredAt;
        uint64 activatedAt;
        uint64 supersededAt;
        address supersededByContractAddress;
    }

    struct ContractSetRecord {
        bytes32 contractSetId;
        bytes32 metadataHash;
        uint64 activatedAt;
        address activatedBy;
        bool active;
    }
}
