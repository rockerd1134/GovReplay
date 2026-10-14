// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { PolicyRegistry } from "./PolicyRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract ProvenanceRegistry {
    ActorRegistry public immutable actorRegistry;
    PolicyRegistry public immutable policyRegistry;

    bytes32 public constant OBSERVATION_ATTESTATION = keccak256("OBSERVATION_ATTESTATION");
    bytes32 public constant EVIDENCE_BUNDLE_ATTESTATION = keccak256("EVIDENCE_BUNDLE_ATTESTATION");
    bytes32 public constant POLICY_DECISION_ATTESTATION = keccak256("POLICY_DECISION_ATTESTATION");
    bytes32 public constant ACTION_PROPOSAL_ATTESTATION = keccak256("ACTION_PROPOSAL_ATTESTATION");
    bytes32 public constant APPROVAL_ATTESTATION = keccak256("APPROVAL_ATTESTATION");
    bytes32 public constant ARTIFACT_ATTESTATION = keccak256("ARTIFACT_ATTESTATION");
    bytes32 public constant DEPLOYMENT_ATTESTATION = keccak256("DEPLOYMENT_ATTESTATION");
    bytes32 public constant AUDIT_REPORT_ATTESTATION = keccak256("AUDIT_REPORT_ATTESTATION");

    mapping(bytes32 attestationHash => GovProvTypes.AttestationRecord record) private _attestations;

    event AttestationAnchored(
        bytes32 indexed attestationHash,
        bytes32 indexed attestationTypeHash,
        bytes32 indexed subjectHash,
        address actor,
        bytes32 policyHash,
        bytes32 parentRoot,
        bytes32 metadataHash,
        bytes32 scopeHash,
        address anchoredBy
    );

    constructor(ActorRegistry actorRegistry_, PolicyRegistry policyRegistry_) {
        GovProvValidation.requireNonZeroAddress(address(actorRegistry_));
        GovProvValidation.requireNonZeroAddress(address(policyRegistry_));
        actorRegistry = actorRegistry_;
        policyRegistry = policyRegistry_;
    }

    function anchorAttestation(
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor,
        bytes32 policyHash,
        bytes32 parentRoot,
        bytes32 metadataHash,
        bytes32 scopeHash
    ) public virtual onlyLedgerWriter {
        GovProvValidation.requireNonZeroHash(attestationHash, "attestationHash");
        GovProvValidation.requireNonZeroHash(attestationTypeHash, "attestationTypeHash");
        GovProvValidation.requireNonZeroHash(subjectHash, "subjectHash");
        GovProvValidation.requireNonZeroAddress(actor);
        _requireActiveHeaderActor(actor);
        if (attestationExists(attestationHash)) {
            revert GovProvErrors.AttestationAlreadyAnchored(attestationHash);
        }
        if (policyHash != bytes32(0) && !policyRegistry.policyExists(policyHash)) {
            revert GovProvErrors.PolicyNotFound(policyHash);
        }

        _attestations[attestationHash] = GovProvTypes.AttestationRecord({
            attestationHash: attestationHash,
            attestationTypeHash: attestationTypeHash,
            subjectHash: subjectHash,
            actor: actor,
            policyHash: policyHash,
            parentRoot: parentRoot,
            metadataHash: metadataHash,
            scopeHash: scopeHash,
            anchoredAt: uint64(block.timestamp),
            exists: true
        });

        emit AttestationAnchored(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            actor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash,
            msg.sender
        );
    }

    function attestationExists(bytes32 attestationHash) public view returns (bool) {
        return _attestations[attestationHash].exists;
    }

    function getAttestation(bytes32 attestationHash)
        external
        view
        returns (GovProvTypes.AttestationRecord memory)
    {
        return _requireAttestation(attestationHash);
    }

    function getAttestationActor(bytes32 attestationHash) external view returns (address) {
        return _requireAttestation(attestationHash).actor;
    }

    function getAttestationPolicy(bytes32 attestationHash) external view returns (bytes32) {
        return _requireAttestation(attestationHash).policyHash;
    }

    function getAttestationType(bytes32 attestationHash) external view returns (bytes32) {
        return _requireAttestation(attestationHash).attestationTypeHash;
    }

    modifier onlyLedgerWriter() {
        _requireLedgerWriter(msg.sender);
        _;
    }

    function _requireAttestation(bytes32 attestationHash)
        private
        view
        returns (GovProvTypes.AttestationRecord storage)
    {
        if (!attestationExists(attestationHash)) {
            revert GovProvErrors.AttestationNotFound(attestationHash);
        }
        return _attestations[attestationHash];
    }

    function _requireLedgerWriter(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
        if (!actorRegistry.hasGovRole(actor, GovProvRoles.LEDGER_WRITER_ROLE)) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.LEDGER_WRITER_ROLE);
        }
    }

    function _requireActiveHeaderActor(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
    }
}
