// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { PolicyRegistry } from "./PolicyRegistry.sol";
import { ProvenanceRegistry } from "./ProvenanceRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";

/// @notice Experimental version enforcing the action actor's replay role at N.
contract HardenedProvenanceRegistry is ProvenanceRegistry {
    constructor(ActorRegistry actorRegistry_, PolicyRegistry policyRegistry_)
        ProvenanceRegistry(actorRegistry_, policyRegistry_)
    {}

    function anchorAttestation(
        bytes32 attestationHash,
        bytes32 attestationTypeHash,
        bytes32 subjectHash,
        address actor,
        bytes32 policyHash,
        bytes32 parentRoot,
        bytes32 metadataHash,
        bytes32 scopeHash
    ) public override {
        if (attestationTypeHash == ACTION_PROPOSAL_ATTESTATION
            && !actorRegistry.hasGovRole(actor, GovProvRoles.DEPLOYER_ROLE)) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.DEPLOYER_ROLE);
        }
        super.anchorAttestation(
            attestationHash, attestationTypeHash, subjectHash, actor,
            policyHash, parentRoot, metadataHash, scopeHash
        );
    }
}
