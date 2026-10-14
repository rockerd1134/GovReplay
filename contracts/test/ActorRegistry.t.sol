// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract ActorRegistryTest is Test {
    ActorRegistry private registry;

    address private governanceAdmin = address(0xA11CE);
    address private nonAdmin = address(0xB0B);
    address private actor = address(0xA100);

    bytes32 private actorIdHash = keccak256("actor:agent-alpha");
    bytes32 private metadataHash = keccak256("metadata:actor:agent-alpha");
    bytes32 private reasonHash = keccak256("reason:test");

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

    function setUp() public {
        vm.prank(governanceAdmin);
        registry = new ActorRegistry(governanceAdmin);
    }

    function testConstructorRegistersGovernanceAdminAsActiveActor() public view {
        assertTrue(registry.isRegisteredActor(governanceAdmin));
        assertTrue(registry.isActiveActor(governanceAdmin));
        assertTrue(registry.hasGovRole(governanceAdmin, GovProvRoles.GOVERNANCE_ADMIN_ROLE));
        assertEq(uint8(registry.getActorType(governanceAdmin)), uint8(GovProvTypes.ActorType.HUMAN));
    }

    function testGovernanceAdminCanRegisterActor() public {
        vm.expectEmit(true, true, false, true, address(registry));
        emit ActorRegistered(
            actor,
            actorIdHash,
            GovProvTypes.ActorType.AGENT,
            metadataHash,
            governanceAdmin
        );

        _registerActor();

        assertTrue(registry.isRegisteredActor(actor));
        assertTrue(registry.isActiveActor(actor));
        assertEq(uint8(registry.getActorType(actor)), uint8(GovProvTypes.ActorType.AGENT));
        assertEq(registry.getActorIdHash(actor), actorIdHash);

        GovProvTypes.ActorRecord memory record = registry.getActor(actor);
        assertEq(record.actor, actor);
        assertEq(record.actorIdHash, actorIdHash);
        assertEq(record.metadataHash, metadataHash);
        assertEq(uint8(record.status), uint8(GovProvTypes.ActorStatus.ACTIVE));
    }

    function testNonAdminCannotRegisterActor() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotRegistered.selector, nonAdmin));
        registry.registerActor(actor, actorIdHash, GovProvTypes.ActorType.AGENT, metadataHash);
    }

    function testDuplicateActorRegistrationReverts() public {
        _registerActor();

        vm.prank(governanceAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorAlreadyRegistered.selector, actor));
        registry.registerActor(actor, actorIdHash, GovProvTypes.ActorType.AGENT, metadataHash);
    }

    function testZeroActorAddressReverts() public {
        vm.prank(governanceAdmin);
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        registry.registerActor(address(0), actorIdHash, GovProvTypes.ActorType.AGENT, metadataHash);
    }

    function testZeroActorIdHashReverts() public {
        vm.prank(governanceAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "actorIdHash"));
        registry.registerActor(actor, bytes32(0), GovProvTypes.ActorType.AGENT, metadataHash);
    }

    function testUnknownActorTypeReverts() public {
        vm.prank(governanceAdmin);
        vm.expectRevert(GovProvErrors.InvalidStatusTransition.selector);
        registry.registerActor(actor, actorIdHash, GovProvTypes.ActorType.UNKNOWN, metadataHash);
    }

    function testAdminCanSuspendActor() public {
        _registerActor();

        vm.expectEmit(true, false, false, true, address(registry));
        emit ActorSuspended(actor, reasonHash, governanceAdmin);

        vm.prank(governanceAdmin);
        registry.suspendActor(actor, reasonHash);

        assertEq(
            uint8(registry.getActorStatus(actor)),
            uint8(GovProvTypes.ActorStatus.SUSPENDED)
        );
    }

    function testSuspendedActorIsNotActive() public {
        _registerActor();
        vm.prank(governanceAdmin);
        registry.suspendActor(actor, reasonHash);

        assertFalse(registry.isActiveActor(actor));
    }

    function testAdminCanResumeSuspendedActor() public {
        _registerActor();
        vm.prank(governanceAdmin);
        registry.suspendActor(actor, reasonHash);

        vm.expectEmit(true, false, false, true, address(registry));
        emit ActorResumed(actor, governanceAdmin);

        vm.prank(governanceAdmin);
        registry.resumeActor(actor);

        assertTrue(registry.isActiveActor(actor));
        assertEq(uint8(registry.getActorStatus(actor)), uint8(GovProvTypes.ActorStatus.ACTIVE));
    }

    function testAdminCanRevokeActor() public {
        _registerActor();

        vm.expectEmit(true, false, false, true, address(registry));
        emit ActorRevoked(actor, reasonHash, governanceAdmin);

        vm.prank(governanceAdmin);
        registry.revokeActor(actor, reasonHash);

        assertEq(uint8(registry.getActorStatus(actor)), uint8(GovProvTypes.ActorStatus.REVOKED));
        assertFalse(registry.isActiveActor(actor));
    }

    function testRevokedActorCannotBeResumed() public {
        _registerActor();
        vm.prank(governanceAdmin);
        registry.revokeActor(actor, reasonHash);

        vm.prank(governanceAdmin);
        vm.expectRevert(GovProvErrors.InvalidStatusTransition.selector);
        registry.resumeActor(actor);
    }

    function testRoleGrantEmitsEvent() public {
        _registerActor();

        vm.expectEmit(true, true, false, true, address(registry));
        emit ActorRoleGranted(actor, GovProvRoles.AGENT_ROLE, governanceAdmin);

        vm.prank(governanceAdmin);
        registry.grantGovRole(actor, GovProvRoles.AGENT_ROLE);

        assertTrue(registry.hasGovRole(actor, GovProvRoles.AGENT_ROLE));
    }

    function testRoleRevokeEmitsEvent() public {
        _registerActor();
        vm.prank(governanceAdmin);
        registry.grantGovRole(actor, GovProvRoles.AGENT_ROLE);

        vm.expectEmit(true, true, false, true, address(registry));
        emit ActorRoleRevoked(actor, GovProvRoles.AGENT_ROLE, governanceAdmin);

        vm.prank(governanceAdmin);
        registry.revokeGovRole(actor, GovProvRoles.AGENT_ROLE);

        assertFalse(registry.hasGovRole(actor, GovProvRoles.AGENT_ROLE));
    }

    function testRevokedActorFailsActiveRoleCheck() public {
        _registerActor();
        vm.prank(governanceAdmin);
        registry.grantGovRole(actor, GovProvRoles.AGENT_ROLE);
        assertTrue(registry.hasGovRole(actor, GovProvRoles.AGENT_ROLE));

        vm.prank(governanceAdmin);
        registry.revokeActor(actor, reasonHash);

        assertFalse(registry.hasGovRole(actor, GovProvRoles.AGENT_ROLE));
    }

    function testInheritedGrantRoleUsesActorRegistryRules() public {
        _registerActor();

        vm.prank(governanceAdmin);
        registry.grantRole(GovProvRoles.AGENT_ROLE, actor);

        assertTrue(registry.hasGovRole(actor, GovProvRoles.AGENT_ROLE));
    }

    function _registerActor() private {
        vm.prank(governanceAdmin);
        registry.registerActor(actor, actorIdHash, GovProvTypes.ActorType.AGENT, metadataHash);
    }
}
