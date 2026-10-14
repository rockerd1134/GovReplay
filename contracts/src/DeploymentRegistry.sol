// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { ApprovalRegistry } from "./ApprovalRegistry.sol";
import { PolicyRegistry } from "./PolicyRegistry.sol";
import { ProvenanceRegistry } from "./ProvenanceRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract DeploymentRegistry {
    ActorRegistry public immutable actorRegistry;
    PolicyRegistry public immutable policyRegistry;
    ProvenanceRegistry public immutable provenanceRegistry;
    ApprovalRegistry public immutable approvalRegistry;

    mapping(bytes32 deploymentIdHash => GovProvTypes.DeploymentRecord record) private _deployments;
    mapping(bytes32 deploymentAttestationHash => bytes32 deploymentIdHash) private
        _deploymentByAttestation;

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

    constructor(
        ActorRegistry actorRegistry_,
        PolicyRegistry policyRegistry_,
        ProvenanceRegistry provenanceRegistry_,
        ApprovalRegistry approvalRegistry_
    ) {
        GovProvValidation.requireNonZeroAddress(address(actorRegistry_));
        GovProvValidation.requireNonZeroAddress(address(policyRegistry_));
        GovProvValidation.requireNonZeroAddress(address(provenanceRegistry_));
        GovProvValidation.requireNonZeroAddress(address(approvalRegistry_));

        actorRegistry = actorRegistry_;
        policyRegistry = policyRegistry_;
        provenanceRegistry = provenanceRegistry_;
        approvalRegistry = approvalRegistry_;
    }

    function recordDeployment(
        bytes32 deploymentIdHash,
        bytes32 deploymentAttestationHash,
        bytes32 actionHash,
        bytes32 artifactHash,
        bytes32 policyHash,
        bytes32 approvalRoot,
        bytes32 environmentHash
    ) external {
        _requireDeploymentWriter(msg.sender);
        GovProvValidation.requireNonZeroHash(deploymentIdHash, "deploymentIdHash");
        GovProvValidation.requireNonZeroHash(deploymentAttestationHash, "deploymentAttestationHash");
        GovProvValidation.requireNonZeroHash(actionHash, "actionHash");
        GovProvValidation.requireNonZeroHash(artifactHash, "artifactHash");
        GovProvValidation.requireNonZeroHash(policyHash, "policyHash");
        GovProvValidation.requireNonZeroHash(approvalRoot, "approvalRoot");
        GovProvValidation.requireNonZeroHash(environmentHash, "environmentHash");

        if (deploymentExists(deploymentIdHash)) {
            revert GovProvErrors.DeploymentAlreadyRecorded(deploymentIdHash);
        }
        bytes32 existingDeploymentId = _deploymentByAttestation[deploymentAttestationHash];
        if (existingDeploymentId != bytes32(0)) {
            revert GovProvErrors.DeploymentAlreadyRecorded(existingDeploymentId);
        }
        if (!provenanceRegistry.attestationExists(actionHash)) {
            revert GovProvErrors.AttestationNotFound(actionHash);
        }
        if (!provenanceRegistry.attestationExists(deploymentAttestationHash)) {
            revert GovProvErrors.AttestationNotFound(deploymentAttestationHash);
        }
        if (!policyRegistry.policyExists(policyHash)) {
            revert GovProvErrors.PolicyNotFound(policyHash);
        }
        if (!_hasValidApproval(actionHash, artifactHash)) {
            revert GovProvErrors.ArtifactApprovalMissing(actionHash, artifactHash);
        }

        _deployments[deploymentIdHash] = GovProvTypes.DeploymentRecord({
            deploymentIdHash: deploymentIdHash,
            deploymentAttestationHash: deploymentAttestationHash,
            actionHash: actionHash,
            artifactHash: artifactHash,
            policyHash: policyHash,
            approvalRoot: approvalRoot,
            environmentHash: environmentHash,
            deployer: msg.sender,
            status: GovProvTypes.DeploymentStatus.RECORDED,
            deployedAt: uint64(block.timestamp),
            revokedAt: 0,
            revocationReasonHash: bytes32(0)
        });
        _deploymentByAttestation[deploymentAttestationHash] = deploymentIdHash;

        emit DeploymentRecorded(
            deploymentIdHash,
            deploymentAttestationHash,
            actionHash,
            artifactHash,
            policyHash,
            approvalRoot,
            environmentHash,
            msg.sender
        );
    }

    function revokeDeployment(bytes32 deploymentIdHash, bytes32 reasonHash) external {
        _requireGovernanceAdmin(msg.sender);
        GovProvTypes.DeploymentRecord storage deployment = _requireDeployment(deploymentIdHash);
        if (deployment.status == GovProvTypes.DeploymentStatus.REVOKED) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        deployment.status = GovProvTypes.DeploymentStatus.REVOKED;
        deployment.revokedAt = uint64(block.timestamp);
        deployment.revocationReasonHash = reasonHash;

        emit DeploymentRevoked(deploymentIdHash, reasonHash, msg.sender);
    }

    function deploymentExists(bytes32 deploymentIdHash) public view returns (bool) {
        return _deployments[deploymentIdHash].status != GovProvTypes.DeploymentStatus.UNKNOWN;
    }

    function getDeployment(bytes32 deploymentIdHash)
        external
        view
        returns (GovProvTypes.DeploymentRecord memory)
    {
        return _requireDeploymentView(deploymentIdHash);
    }

    function getDeploymentByAttestation(bytes32 deploymentAttestationHash)
        external
        view
        returns (bytes32)
    {
        bytes32 deploymentIdHash = _deploymentByAttestation[deploymentAttestationHash];
        if (deploymentIdHash == bytes32(0)) {
            revert GovProvErrors.DeploymentNotFound(deploymentAttestationHash);
        }
        return deploymentIdHash;
    }

    function getDeploymentStatus(bytes32 deploymentIdHash)
        external
        view
        returns (GovProvTypes.DeploymentStatus)
    {
        return _requireDeploymentView(deploymentIdHash).status;
    }

    function _hasValidApproval(bytes32 actionHash, bytes32 artifactHash)
        private
        view
        returns (bool)
    {
        return approvalRegistry.hasValidApprovalForArtifact(
            actionHash, artifactHash, GovProvRoles.APPROVER_ROLE
        )
            || approvalRegistry.hasValidApprovalForArtifact(
                actionHash, artifactHash, GovProvRoles.SECURITY_APPROVER_ROLE
            );
    }

    function _requireDeploymentWriter(address actor) private view {
        _requireActiveActor(actor);
        if (
            !actorRegistry.hasGovRole(actor, GovProvRoles.DEPLOYER_ROLE)
                && !actorRegistry.hasGovRole(actor, GovProvRoles.LEDGER_WRITER_ROLE)
        ) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.DEPLOYER_ROLE);
        }
    }

    function _requireGovernanceAdmin(address actor) private view {
        _requireActiveActor(actor);
        if (!actorRegistry.hasGovRole(actor, GovProvRoles.GOVERNANCE_ADMIN_ROLE)) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.GOVERNANCE_ADMIN_ROLE);
        }
    }

    function _requireActiveActor(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
    }

    function _requireDeployment(bytes32 deploymentIdHash)
        private
        view
        returns (GovProvTypes.DeploymentRecord storage)
    {
        if (!deploymentExists(deploymentIdHash)) {
            revert GovProvErrors.DeploymentNotFound(deploymentIdHash);
        }
        return _deployments[deploymentIdHash];
    }

    function _requireDeploymentView(bytes32 deploymentIdHash)
        private
        view
        returns (GovProvTypes.DeploymentRecord storage)
    {
        if (!deploymentExists(deploymentIdHash)) {
            revert GovProvErrors.DeploymentNotFound(deploymentIdHash);
        }
        return _deployments[deploymentIdHash];
    }
}
