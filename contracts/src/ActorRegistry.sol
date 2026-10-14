// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract ActorRegistry is AccessControl {
    bytes32 public constant GOVERNANCE_ADMIN_ROLE = GovProvRoles.GOVERNANCE_ADMIN_ROLE;

    mapping(address actor => GovProvTypes.ActorRecord record) private _actors;

    event ActorRegistered(
        address indexed actor,
        bytes32 indexed actorIdHash,
        GovProvTypes.ActorType actorType,
        bytes32 metadataHash,
        address registeredBy
    );
    event ActorSuspended(address indexed actor, bytes32 reasonHash, address suspendedBy);
    event ActorResumed(address indexed actor, address resumedBy);
    event ActorRevoked(address indexed actor, bytes32 reasonHash, address revokedBy);
    event ActorRoleGranted(address indexed actor, bytes32 indexed role, address grantedBy);
    event ActorRoleRevoked(address indexed actor, bytes32 indexed role, address revokedBy);

    constructor(address governanceAdmin) {
        GovProvValidation.requireNonZeroAddress(governanceAdmin);

        _registerActor(
            governanceAdmin,
            keccak256(abi.encodePacked("govprov:bootstrap-governance-admin", governanceAdmin)),
            GovProvTypes.ActorType.HUMAN,
            keccak256("govprov:bootstrap-governance-admin:metadata"),
            governanceAdmin
        );
        _grantRole(DEFAULT_ADMIN_ROLE, governanceAdmin);
        _grantRole(GOVERNANCE_ADMIN_ROLE, governanceAdmin);
    }

    function registerActor(
        address actor,
        bytes32 actorIdHash,
        GovProvTypes.ActorType actorType,
        bytes32 metadataHash
    ) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        GovProvValidation.requireNonZeroAddress(actor);
        GovProvValidation.requireNonZeroHash(actorIdHash, "actorIdHash");
        if (isRegisteredActor(actor)) {
            revert GovProvErrors.ActorAlreadyRegistered(actor);
        }
        if (actorType == GovProvTypes.ActorType.UNKNOWN) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        _registerActor(actor, actorIdHash, actorType, metadataHash, msg.sender);
    }

    function suspendActor(
        address actor,
        bytes32 reasonHash
    ) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _requireRegisteredActor(actor);
        if (_actors[actor].status != GovProvTypes.ActorStatus.ACTIVE) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        _actors[actor].status = GovProvTypes.ActorStatus.SUSPENDED;
        _actors[actor].suspendedAt = uint64(block.timestamp);

        emit ActorSuspended(actor, reasonHash, msg.sender);
    }

    function resumeActor(address actor) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _requireRegisteredActor(actor);
        if (_actors[actor].status != GovProvTypes.ActorStatus.SUSPENDED) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        _actors[actor].status = GovProvTypes.ActorStatus.ACTIVE;
        _actors[actor].suspendedAt = 0;

        emit ActorResumed(actor, msg.sender);
    }

    function revokeActor(
        address actor,
        bytes32 reasonHash
    ) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _requireRegisteredActor(actor);
        if (_actors[actor].status == GovProvTypes.ActorStatus.REVOKED) {
            revert GovProvErrors.ActorAlreadyRevoked(actor);
        }

        _actors[actor].status = GovProvTypes.ActorStatus.REVOKED;
        _actors[actor].revokedAt = uint64(block.timestamp);
        _actors[actor].revocationReasonHash = reasonHash;

        emit ActorRevoked(actor, reasonHash, msg.sender);
    }

    function grantGovRole(
        address actor,
        bytes32 role
    ) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _grantGovRole(actor, role, msg.sender);
    }

    function revokeGovRole(
        address actor,
        bytes32 role
    ) external onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _revokeGovRole(actor, role, msg.sender);
    }

    function grantRole(
        bytes32 role,
        address account
    ) public override onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _grantGovRole(account, role, msg.sender);
    }

    function revokeRole(
        bytes32 role,
        address account
    ) public override onlyActiveRole(GOVERNANCE_ADMIN_ROLE) {
        _revokeGovRole(account, role, msg.sender);
    }

    function renounceRole(bytes32 role, address callerConfirmation) public override {
        if (callerConfirmation != msg.sender) {
            revert AccessControlBadConfirmation();
        }

        if (_revokeRole(role, callerConfirmation)) {
            emit ActorRoleRevoked(callerConfirmation, role, msg.sender);
        }
    }

    function isRegisteredActor(address actor) public view returns (bool) {
        return _actors[actor].status != GovProvTypes.ActorStatus.UNKNOWN;
    }

    function isActiveActor(address actor) public view returns (bool) {
        return _actors[actor].status == GovProvTypes.ActorStatus.ACTIVE;
    }

    function getActorStatus(address actor) external view returns (GovProvTypes.ActorStatus) {
        return _actors[actor].status;
    }

    function getActorType(address actor) external view returns (GovProvTypes.ActorType) {
        return _actors[actor].actorType;
    }

    function getActorIdHash(address actor) external view returns (bytes32) {
        return _actors[actor].actorIdHash;
    }

    function hasGovRole(address actor, bytes32 role) public view returns (bool) {
        return isActiveActor(actor) && hasRole(role, actor);
    }

    function getActor(address actor) external view returns (GovProvTypes.ActorRecord memory) {
        _requireRegisteredActor(actor);
        return _actors[actor];
    }

    modifier onlyActiveRole(bytes32 role) {
        _requireActiveRole(msg.sender, role);
        _;
    }

    function _registerActor(
        address actor,
        bytes32 actorIdHash,
        GovProvTypes.ActorType actorType,
        bytes32 metadataHash,
        address registeredBy
    ) private {
        _actors[actor] = GovProvTypes.ActorRecord({
            actor: actor,
            actorIdHash: actorIdHash,
            metadataHash: metadataHash,
            actorType: actorType,
            status: GovProvTypes.ActorStatus.ACTIVE,
            registeredAt: uint64(block.timestamp),
            suspendedAt: 0,
            revokedAt: 0,
            revocationReasonHash: bytes32(0)
        });

        emit ActorRegistered(actor, actorIdHash, actorType, metadataHash, registeredBy);
    }

    function _grantGovRole(address actor, bytes32 role, address grantedBy) private {
        _requireActiveActor(actor);
        if (_grantRole(role, actor)) {
            emit ActorRoleGranted(actor, role, grantedBy);
        }
    }

    function _revokeGovRole(address actor, bytes32 role, address revokedBy) private {
        _requireRegisteredActor(actor);
        if (_revokeRole(role, actor)) {
            emit ActorRoleRevoked(actor, role, revokedBy);
        }
    }

    function _requireRegisteredActor(address actor) private view {
        if (!isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
    }

    function _requireActiveActor(address actor) private view {
        _requireRegisteredActor(actor);
        if (!isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
    }

    function _requireActiveRole(address actor, bytes32 role) private view {
        _requireActiveActor(actor);
        if (!hasRole(role, actor)) {
            revert GovProvErrors.MissingRole(actor, role);
        }
    }
}
