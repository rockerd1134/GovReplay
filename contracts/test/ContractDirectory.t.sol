// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ContractDirectory } from "../src/ContractDirectory.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract ContractDirectoryTest is Test {
    ActorRegistry private actorRegistry;
    ContractDirectory private contractDirectory;

    address private governanceAdmin = address(0xA11CE);
    address private nonAdmin = address(0xB0B);
    address private actorRegistryAddress = address(0xA100);
    address private policyRegistryAddress = address(0xA200);
    address private deploymentRegistryAddressV1 = address(0xD100);
    address private deploymentRegistryAddressV2 = address(0xD200);

    bytes32 private actorRegistryNameHash = keccak256("ACTOR_REGISTRY");
    bytes32 private policyRegistryNameHash = keccak256("POLICY_REGISTRY");
    bytes32 private deploymentRegistryNameHash = keccak256("DEPLOYMENT_REGISTRY");
    bytes32 private versionHashV1 = keccak256("version:v1");
    bytes32 private versionHashV2 = keccak256("version:v2");
    bytes32 private sourceHash = keccak256("source:v1");
    bytes32 private abiHash = keccak256("abi:v1");
    bytes32 private metadataHash = keccak256("metadata:v1");
    bytes32 private contractSetIdV1 = keccak256("contract-set:v1");
    bytes32 private contractSetIdV2 = keccak256("contract-set:v2");
    bytes32 private reasonHash = keccak256("reason:test");

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

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        contractDirectory = new ContractDirectory(actorRegistry);

        vm.prank(governanceAdmin);
        actorRegistry.registerActor(
            nonAdmin,
            keccak256("actor:non-admin"),
            GovProvTypes.ActorType.HUMAN,
            keccak256("metadata:non-admin")
        );
    }

    function testConstructorRejectsZeroActorRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new ContractDirectory(ActorRegistry(address(0)));
    }

    function testGovernanceAdminCanRegisterContract() public {
        vm.expectEmit(true, true, true, true, address(contractDirectory));
        emit ContractRegistered(
            deploymentRegistryNameHash,
            deploymentRegistryAddressV1,
            versionHashV1,
            sourceHash,
            abiHash,
            metadataHash,
            governanceAdmin
        );

        _registerContract(deploymentRegistryNameHash, deploymentRegistryAddressV1, versionHashV1);

        assertTrue(
            contractDirectory.isRegisteredContract(
                deploymentRegistryNameHash, deploymentRegistryAddressV1
            )
        );

        GovProvTypes.ContractRecord memory record = contractDirectory.getRegisteredContract(
            deploymentRegistryNameHash, deploymentRegistryAddressV1
        );
        assertEq(record.nameHash, deploymentRegistryNameHash);
        assertEq(record.contractAddress, deploymentRegistryAddressV1);
        assertEq(record.versionHash, versionHashV1);
        assertEq(record.sourceHash, sourceHash);
        assertEq(record.abiHash, abiHash);
        assertEq(record.metadataHash, metadataHash);
        assertEq(record.registeredBy, governanceAdmin);
        assertEq(uint8(record.status), uint8(GovProvTypes.ContractStatus.REGISTERED));
        assertGt(record.registeredAt, 0);
    }

    function testNonAdminCannotRegisterContract() public {
        vm.prank(nonAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, nonAdmin, GovProvRoles.GOVERNANCE_ADMIN_ROLE
            )
        );
        contractDirectory.registerContract(
            deploymentRegistryNameHash,
            deploymentRegistryAddressV1,
            versionHashV1,
            sourceHash,
            abiHash,
            metadataHash
        );
    }

    function testZeroNameContractAddressAndVersionRevert() public {
        vm.prank(governanceAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "nameHash"));
        contractDirectory.registerContract(
            bytes32(0),
            deploymentRegistryAddressV1,
            versionHashV1,
            sourceHash,
            abiHash,
            metadataHash
        );

        vm.prank(governanceAdmin);
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        contractDirectory.registerContract(
            deploymentRegistryNameHash, address(0), versionHashV1, sourceHash, abiHash, metadataHash
        );

        vm.prank(governanceAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "versionHash"));
        contractDirectory.registerContract(
            deploymentRegistryNameHash,
            deploymentRegistryAddressV1,
            bytes32(0),
            sourceHash,
            abiHash,
            metadataHash
        );
    }

    function testGovernanceAdminCanActivateContractSet() public {
        _registerContract(actorRegistryNameHash, actorRegistryAddress, versionHashV1);
        _registerContract(policyRegistryNameHash, policyRegistryAddress, versionHashV1);

        bytes32[] memory names = new bytes32[](2);
        names[0] = actorRegistryNameHash;
        names[1] = policyRegistryNameHash;
        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = actorRegistryAddress;
        contractAddresses[1] = policyRegistryAddress;

        vm.expectEmit(true, false, false, true, address(contractDirectory));
        emit ContractSetActivated(contractSetIdV1, metadataHash, governanceAdmin);
        vm.expectEmit(true, true, true, true, address(contractDirectory));
        emit ContractSetMember(contractSetIdV1, actorRegistryNameHash, actorRegistryAddress);
        vm.expectEmit(true, true, true, true, address(contractDirectory));
        emit ContractSetMember(contractSetIdV1, policyRegistryNameHash, policyRegistryAddress);

        vm.prank(governanceAdmin);
        contractDirectory.activateContractSet(
            contractSetIdV1, metadataHash, names, contractAddresses
        );

        assertEq(contractDirectory.getActiveContractSet(), contractSetIdV1);
        assertEq(
            contractDirectory.getContract(contractSetIdV1, actorRegistryNameHash),
            actorRegistryAddress
        );
        assertEq(
            contractDirectory.getContract(contractSetIdV1, policyRegistryNameHash),
            policyRegistryAddress
        );
    }

    function testMismatchedActivationArraysRevert() public {
        bytes32[] memory names = new bytes32[](1);
        names[0] = actorRegistryNameHash;
        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = actorRegistryAddress;
        contractAddresses[1] = policyRegistryAddress;

        vm.prank(governanceAdmin);
        vm.expectRevert(GovProvErrors.ArrayLengthMismatch.selector);
        contractDirectory.activateContractSet(
            contractSetIdV1, metadataHash, names, contractAddresses
        );
    }

    function testZeroContractSetIdReverts() public {
        bytes32[] memory names = new bytes32[](0);
        address[] memory contractAddresses = new address[](0);

        vm.prank(governanceAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "contractSetId"));
        contractDirectory.activateContractSet(bytes32(0), metadataHash, names, contractAddresses);
    }

    function testActivationWithUnregisteredContractPairReverts() public {
        bytes32[] memory names = new bytes32[](1);
        names[0] = actorRegistryNameHash;
        address[] memory contractAddresses = new address[](1);
        contractAddresses[0] = actorRegistryAddress;

        vm.prank(governanceAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.ContractNotFound.selector, actorRegistryNameHash, actorRegistryAddress
            )
        );
        contractDirectory.activateContractSet(
            contractSetIdV1, metadataHash, names, contractAddresses
        );
    }

    function testContractLookupReturnsActiveAndHistoricalSets() public {
        _registerContract(deploymentRegistryNameHash, deploymentRegistryAddressV1, versionHashV1);
        _registerContract(deploymentRegistryNameHash, deploymentRegistryAddressV2, versionHashV2);

        _activateSingleContractSet(
            contractSetIdV1, deploymentRegistryNameHash, deploymentRegistryAddressV1
        );
        _activateSingleContractSet(
            contractSetIdV2, deploymentRegistryNameHash, deploymentRegistryAddressV2
        );

        assertEq(contractDirectory.getActiveContractSet(), contractSetIdV2);
        assertEq(
            contractDirectory.getContract(contractSetIdV1, deploymentRegistryNameHash),
            deploymentRegistryAddressV1
        );
        assertEq(
            contractDirectory.getContract(contractSetIdV2, deploymentRegistryNameHash),
            deploymentRegistryAddressV2
        );
    }

    function testSupersessionEventIsEmittedForRegisteredPair() public {
        _registerContract(deploymentRegistryNameHash, deploymentRegistryAddressV1, versionHashV1);
        _registerContract(deploymentRegistryNameHash, deploymentRegistryAddressV2, versionHashV2);

        vm.expectEmit(true, true, true, true, address(contractDirectory));
        emit ContractSuperseded(
            deploymentRegistryNameHash,
            deploymentRegistryAddressV1,
            deploymentRegistryAddressV2,
            reasonHash,
            governanceAdmin
        );

        vm.prank(governanceAdmin);
        contractDirectory.supersedeContract(
            deploymentRegistryNameHash,
            deploymentRegistryAddressV1,
            deploymentRegistryAddressV2,
            reasonHash
        );

        GovProvTypes.ContractRecord memory oldRecord = contractDirectory.getRegisteredContract(
            deploymentRegistryNameHash, deploymentRegistryAddressV1
        );
        assertEq(uint8(oldRecord.status), uint8(GovProvTypes.ContractStatus.SUPERSEDED));
        assertEq(oldRecord.supersededByContractAddress, deploymentRegistryAddressV2);
        assertGt(oldRecord.supersededAt, 0);
    }

    function _registerContract(bytes32 nameHash, address contractAddress, bytes32 versionHash)
        private
    {
        vm.prank(governanceAdmin);
        contractDirectory.registerContract(
            nameHash, contractAddress, versionHash, sourceHash, abiHash, metadataHash
        );
    }

    function _activateSingleContractSet(
        bytes32 contractSetId,
        bytes32 nameHash,
        address contractAddress
    ) private {
        bytes32[] memory names = new bytes32[](1);
        names[0] = nameHash;
        address[] memory contractAddresses = new address[](1);
        contractAddresses[0] = contractAddress;

        vm.prank(governanceAdmin);
        contractDirectory.activateContractSet(contractSetId, metadataHash, names, contractAddresses);
    }
}
