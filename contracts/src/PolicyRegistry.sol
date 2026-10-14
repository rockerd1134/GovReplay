// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract PolicyRegistry {
    ActorRegistry public immutable actorRegistry;

    mapping(bytes32 policyHash => GovProvTypes.PolicyRecord record) private _policies;
    mapping(bytes32 scopeHash => bytes32 policyHash) private _activePolicyByScope;

    event PolicyRegistered(
        bytes32 indexed policyHash,
        bytes32 indexed parentPolicyHash,
        bytes32 indexed scopeHash,
        bytes32 metadataHash,
        address registeredBy
    );
    event PolicyActivated(
        bytes32 indexed policyHash, bytes32 indexed scopeHash, address activatedBy
    );
    event PolicySuperseded(
        bytes32 indexed oldPolicyHash,
        bytes32 indexed newPolicyHash,
        bytes32 indexed scopeHash,
        address supersededBy
    );
    event PolicyRevoked(bytes32 indexed policyHash, bytes32 reasonHash, address revokedBy);

    constructor(ActorRegistry actorRegistry_) {
        GovProvValidation.requireNonZeroAddress(address(actorRegistry_));
        actorRegistry = actorRegistry_;
    }

    function registerPolicy(
        bytes32 policyHash,
        bytes32 parentPolicyHash,
        bytes32 metadataHash,
        bytes32 scopeHash
    ) external onlyPolicyAdmin {
        GovProvValidation.requireNonZeroHash(policyHash, "policyHash");
        GovProvValidation.requireNonZeroHash(scopeHash, "scopeHash");
        if (policyExists(policyHash)) {
            revert GovProvErrors.PolicyAlreadyRegistered(policyHash);
        }
        if (parentPolicyHash != bytes32(0) && !policyExists(parentPolicyHash)) {
            revert GovProvErrors.PolicyNotFound(parentPolicyHash);
        }

        _policies[policyHash] = GovProvTypes.PolicyRecord({
            policyHash: policyHash,
            parentPolicyHash: parentPolicyHash,
            metadataHash: metadataHash,
            scopeHash: scopeHash,
            status: GovProvTypes.PolicyStatus.REGISTERED,
            registeredBy: msg.sender,
            registeredAt: uint64(block.timestamp),
            activatedAt: 0,
            supersededAt: 0,
            revokedAt: 0,
            supersededByPolicyHash: bytes32(0),
            revocationReasonHash: bytes32(0)
        });

        emit PolicyRegistered(policyHash, parentPolicyHash, scopeHash, metadataHash, msg.sender);
    }

    function activatePolicy(bytes32 policyHash) external onlyPolicyAdmin {
        GovProvTypes.PolicyRecord storage policy = _requirePolicy(policyHash);
        if (policy.status == GovProvTypes.PolicyStatus.REVOKED) {
            revert GovProvErrors.PolicyRevoked(policyHash);
        }
        if (policy.status != GovProvTypes.PolicyStatus.REGISTERED) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        bytes32 scopeHash = policy.scopeHash;
        bytes32 previousPolicyHash = _activePolicyByScope[scopeHash];
        if (previousPolicyHash != bytes32(0) && previousPolicyHash != policyHash) {
            GovProvTypes.PolicyRecord storage previousPolicy = _policies[previousPolicyHash];
            previousPolicy.status = GovProvTypes.PolicyStatus.SUPERSEDED;
            previousPolicy.supersededAt = uint64(block.timestamp);
            previousPolicy.supersededByPolicyHash = policyHash;
            emit PolicySuperseded(previousPolicyHash, policyHash, scopeHash, msg.sender);
        }

        policy.status = GovProvTypes.PolicyStatus.ACTIVE;
        policy.activatedAt = uint64(block.timestamp);
        _activePolicyByScope[scopeHash] = policyHash;

        emit PolicyActivated(policyHash, scopeHash, msg.sender);
    }

    function revokePolicy(bytes32 policyHash, bytes32 reasonHash) external onlyPolicyAdmin {
        GovProvTypes.PolicyRecord storage policy = _requirePolicy(policyHash);
        if (policy.status == GovProvTypes.PolicyStatus.REVOKED) {
            revert GovProvErrors.PolicyRevoked(policyHash);
        }

        if (_activePolicyByScope[policy.scopeHash] == policyHash) {
            _activePolicyByScope[policy.scopeHash] = bytes32(0);
        }

        policy.status = GovProvTypes.PolicyStatus.REVOKED;
        policy.revokedAt = uint64(block.timestamp);
        policy.revocationReasonHash = reasonHash;

        emit PolicyRevoked(policyHash, reasonHash, msg.sender);
    }

    function policyExists(bytes32 policyHash) public view returns (bool) {
        return _policies[policyHash].status != GovProvTypes.PolicyStatus.UNKNOWN;
    }

    function isPolicyActive(bytes32 policyHash) public view returns (bool) {
        GovProvTypes.PolicyRecord storage policy = _policies[policyHash];
        return policy.status == GovProvTypes.PolicyStatus.ACTIVE
            && _activePolicyByScope[policy.scopeHash] == policyHash;
    }

    function getActivePolicy(bytes32 scopeHash) external view returns (bytes32) {
        bytes32 policyHash = _activePolicyByScope[scopeHash];
        if (policyHash == bytes32(0)) {
            revert GovProvErrors.NoActivePolicy(scopeHash);
        }
        return policyHash;
    }

    function getPolicyScope(bytes32 policyHash) external view returns (bytes32) {
        return _requirePolicyView(policyHash).scopeHash;
    }

    function getPolicyStatus(bytes32 policyHash)
        external
        view
        returns (GovProvTypes.PolicyStatus)
    {
        return _requirePolicyView(policyHash).status;
    }

    function getPolicy(bytes32 policyHash)
        external
        view
        returns (GovProvTypes.PolicyRecord memory)
    {
        return _requirePolicyView(policyHash);
    }

    modifier onlyPolicyAdmin() {
        _requirePolicyAdmin(msg.sender);
        _;
    }

    function _requirePolicy(bytes32 policyHash)
        private
        view
        returns (GovProvTypes.PolicyRecord storage)
    {
        if (!policyExists(policyHash)) {
            revert GovProvErrors.PolicyNotFound(policyHash);
        }
        return _policies[policyHash];
    }

    function _requirePolicyView(bytes32 policyHash)
        private
        view
        returns (GovProvTypes.PolicyRecord storage)
    {
        if (!policyExists(policyHash)) {
            revert GovProvErrors.PolicyNotFound(policyHash);
        }
        return _policies[policyHash];
    }

    function _requirePolicyAdmin(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
        if (!actorRegistry.hasGovRole(actor, GovProvRoles.POLICY_ADMIN_ROLE)) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.POLICY_ADMIN_ROLE);
        }
    }
}
