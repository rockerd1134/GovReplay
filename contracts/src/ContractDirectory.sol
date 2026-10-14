// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { ActorRegistry } from "./ActorRegistry.sol";
import { GovProvErrors } from "./lib/GovProvErrors.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";
import { GovProvTypes } from "./lib/GovProvTypes.sol";
import { GovProvValidation } from "./lib/GovProvValidation.sol";

contract ContractDirectory {
    ActorRegistry public immutable actorRegistry;

    mapping(
        bytes32 nameHash => mapping(address contractAddress => GovProvTypes.ContractRecord record)
    ) private _contracts;
    mapping(bytes32 contractSetId => mapping(bytes32 nameHash => address contractAddress)) private
        _contractSetMembers;
    mapping(bytes32 contractSetId => GovProvTypes.ContractSetRecord record) private _contractSets;

    bytes32 private _activeContractSetId;

    event ContractRegistered(
        bytes32 indexed nameHash,
        address indexed contractAddress,
        bytes32 indexed versionHash,
        bytes32 sourceHash,
        bytes32 abiHash,
        bytes32 metadataHash,
        address registeredBy
    );
    event ContractSetActivated(
        bytes32 indexed contractSetId, bytes32 metadataHash, address activatedBy
    );
    event ContractSetMember(
        bytes32 indexed contractSetId, bytes32 indexed nameHash, address indexed contractAddress
    );
    event ContractSuperseded(
        bytes32 indexed nameHash,
        address indexed oldContract,
        address indexed newContract,
        bytes32 reasonHash,
        address supersededBy
    );

    constructor(ActorRegistry actorRegistry_) {
        GovProvValidation.requireNonZeroAddress(address(actorRegistry_));
        actorRegistry = actorRegistry_;
    }

    function registerContract(
        bytes32 nameHash,
        address contractAddress,
        bytes32 versionHash,
        bytes32 sourceHash,
        bytes32 abiHash,
        bytes32 metadataHash
    ) external {
        _requireGovernanceAdmin(msg.sender);
        GovProvValidation.requireNonZeroHash(nameHash, "nameHash");
        GovProvValidation.requireNonZeroAddress(contractAddress);
        GovProvValidation.requireNonZeroHash(versionHash, "versionHash");
        if (isRegisteredContract(nameHash, contractAddress)) {
            revert GovProvErrors.ContractAlreadyRegistered(nameHash, contractAddress);
        }

        _contracts[nameHash][contractAddress] = GovProvTypes.ContractRecord({
            nameHash: nameHash,
            contractAddress: contractAddress,
            versionHash: versionHash,
            sourceHash: sourceHash,
            abiHash: abiHash,
            metadataHash: metadataHash,
            status: GovProvTypes.ContractStatus.REGISTERED,
            registeredBy: msg.sender,
            registeredAt: uint64(block.timestamp),
            activatedAt: 0,
            supersededAt: 0,
            supersededByContractAddress: address(0)
        });

        emit ContractRegistered(
            nameHash, contractAddress, versionHash, sourceHash, abiHash, metadataHash, msg.sender
        );
    }

    function activateContractSet(
        bytes32 contractSetId,
        bytes32 metadataHash,
        bytes32[] calldata nameHashes,
        address[] calldata contractAddresses
    ) external {
        _requireGovernanceAdmin(msg.sender);
        GovProvValidation.requireNonZeroHash(contractSetId, "contractSetId");
        if (nameHashes.length != contractAddresses.length) {
            revert GovProvErrors.ArrayLengthMismatch();
        }
        if (_contractSets[contractSetId].activatedAt != 0) {
            revert GovProvErrors.InvalidStatusTransition();
        }

        bytes32 previousContractSetId = _activeContractSetId;
        if (previousContractSetId != bytes32(0)) {
            _contractSets[previousContractSetId].active = false;
        }

        _contractSets[contractSetId] = GovProvTypes.ContractSetRecord({
            contractSetId: contractSetId,
            metadataHash: metadataHash,
            activatedAt: uint64(block.timestamp),
            activatedBy: msg.sender,
            active: true
        });
        _activeContractSetId = contractSetId;

        emit ContractSetActivated(contractSetId, metadataHash, msg.sender);

        for (uint256 i = 0; i < nameHashes.length; i++) {
            bytes32 nameHash = nameHashes[i];
            address contractAddress = contractAddresses[i];
            GovProvValidation.requireNonZeroHash(nameHash, "nameHash");
            GovProvValidation.requireNonZeroAddress(contractAddress);

            GovProvTypes.ContractRecord storage contractRecord =
                _requireRegisteredContract(nameHash, contractAddress);
            contractRecord.status = GovProvTypes.ContractStatus.ACTIVE;
            contractRecord.activatedAt = uint64(block.timestamp);

            _contractSetMembers[contractSetId][nameHash] = contractAddress;
            emit ContractSetMember(contractSetId, nameHash, contractAddress);
        }
    }

    function supersedeContract(
        bytes32 nameHash,
        address oldContract,
        address newContract,
        bytes32 reasonHash
    ) external {
        _requireGovernanceAdmin(msg.sender);
        GovProvValidation.requireNonZeroHash(nameHash, "nameHash");
        GovProvValidation.requireNonZeroAddress(oldContract);
        GovProvValidation.requireNonZeroAddress(newContract);

        GovProvTypes.ContractRecord storage oldRecord =
            _requireRegisteredContract(nameHash, oldContract);
        _requireRegisteredContract(nameHash, newContract);

        oldRecord.status = GovProvTypes.ContractStatus.SUPERSEDED;
        oldRecord.supersededAt = uint64(block.timestamp);
        oldRecord.supersededByContractAddress = newContract;

        emit ContractSuperseded(nameHash, oldContract, newContract, reasonHash, msg.sender);
    }

    function getActiveContractSet() external view returns (bytes32) {
        return _activeContractSetId;
    }

    function getContract(bytes32 contractSetId, bytes32 nameHash) external view returns (address) {
        address contractAddress = _contractSetMembers[contractSetId][nameHash];
        if (contractAddress == address(0)) {
            revert GovProvErrors.ContractNotFound(nameHash, address(0));
        }
        return contractAddress;
    }

    function isRegisteredContract(bytes32 nameHash, address contractAddress)
        public
        view
        returns (bool)
    {
        return _contracts[nameHash][contractAddress].status != GovProvTypes.ContractStatus.UNKNOWN;
    }

    function getRegisteredContract(bytes32 nameHash, address contractAddress)
        external
        view
        returns (GovProvTypes.ContractRecord memory)
    {
        return _requireRegisteredContract(nameHash, contractAddress);
    }

    function _requireGovernanceAdmin(address actor) private view {
        if (!actorRegistry.isRegisteredActor(actor)) {
            revert GovProvErrors.ActorNotRegistered(actor);
        }
        if (!actorRegistry.isActiveActor(actor)) {
            revert GovProvErrors.ActorNotActive(actor);
        }
        if (!actorRegistry.hasGovRole(actor, GovProvRoles.GOVERNANCE_ADMIN_ROLE)) {
            revert GovProvErrors.MissingRole(actor, GovProvRoles.GOVERNANCE_ADMIN_ROLE);
        }
    }

    function _requireRegisteredContract(bytes32 nameHash, address contractAddress)
        private
        view
        returns (GovProvTypes.ContractRecord storage)
    {
        if (!isRegisteredContract(nameHash, contractAddress)) {
            revert GovProvErrors.ContractNotFound(nameHash, contractAddress);
        }
        return _contracts[nameHash][contractAddress];
    }
}
