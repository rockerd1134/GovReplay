// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract PolicyRegistryTest is Test {
    ActorRegistry private actorRegistry;
    PolicyRegistry private policyRegistry;

    address private governanceAdmin = address(0xA11CE);
    address private policyAdmin = address(0xBEEF);
    address private nonPolicyAdmin = address(0xCAFE);

    bytes32 private policyHash = keccak256("policy:v1");
    bytes32 private policyHashV2 = keccak256("policy:v2");
    bytes32 private metadataHash = keccak256("metadata:policy:v1");
    bytes32 private metadataHashV2 = keccak256("metadata:policy:v2");
    bytes32 private scopeHash = keccak256("scope:runbook_update");
    bytes32 private reasonHash = keccak256("reason:policy-revoked");

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

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        policyRegistry = new PolicyRegistry(actorRegistry);

        _registerActor(policyAdmin, "actor:policy-admin");
        _registerActor(nonPolicyAdmin, "actor:non-policy-admin");

        vm.prank(governanceAdmin);
        actorRegistry.grantGovRole(policyAdmin, GovProvRoles.POLICY_ADMIN_ROLE);
    }

    function testConstructorRejectsZeroActorRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new PolicyRegistry(ActorRegistry(address(0)));
    }

    function testPolicyAdminCanRegisterPolicy() public {
        vm.expectEmit(true, true, true, true, address(policyRegistry));
        emit PolicyRegistered(policyHash, bytes32(0), scopeHash, metadataHash, policyAdmin);

        _registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);

        assertTrue(policyRegistry.policyExists(policyHash));
        assertEq(policyRegistry.getPolicyScope(policyHash), scopeHash);
        assertEq(
            uint8(policyRegistry.getPolicyStatus(policyHash)),
            uint8(GovProvTypes.PolicyStatus.REGISTERED)
        );

        GovProvTypes.PolicyRecord memory record = policyRegistry.getPolicy(policyHash);
        assertEq(record.policyHash, policyHash);
        assertEq(record.parentPolicyHash, bytes32(0));
        assertEq(record.metadataHash, metadataHash);
        assertEq(record.scopeHash, scopeHash);
        assertEq(record.registeredBy, policyAdmin);
    }

    function testNonPolicyAdminCannotRegisterPolicy() public {
        vm.prank(nonPolicyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, nonPolicyAdmin, GovProvRoles.POLICY_ADMIN_ROLE
            )
        );
        policyRegistry.registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);
    }

    function testInactivePolicyAdminCannotRegisterPolicy() public {
        vm.prank(governanceAdmin);
        actorRegistry.suspendActor(policyAdmin, reasonHash);

        vm.prank(policyAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, policyAdmin));
        policyRegistry.registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);
    }

    function testDuplicatePolicyRegistrationReverts() public {
        _registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);

        vm.prank(policyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.PolicyAlreadyRegistered.selector, policyHash)
        );
        policyRegistry.registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);
    }

    function testZeroPolicyHashReverts() public {
        vm.prank(policyAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "policyHash"));
        policyRegistry.registerPolicy(bytes32(0), bytes32(0), metadataHash, scopeHash);
    }

    function testZeroScopeHashReverts() public {
        vm.prank(policyAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "scopeHash"));
        policyRegistry.registerPolicy(policyHash, bytes32(0), metadataHash, bytes32(0));
    }

    function testPolicyWithUnknownParentReverts() public {
        bytes32 unknownParent = keccak256("policy:missing-parent");

        vm.prank(policyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.PolicyNotFound.selector, unknownParent)
        );
        policyRegistry.registerPolicy(policyHash, unknownParent, metadataHash, scopeHash);
    }

    function testPolicyAdminCanActivatePolicy() public {
        _registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);

        vm.expectEmit(true, true, false, true, address(policyRegistry));
        emit PolicyActivated(policyHash, scopeHash, policyAdmin);

        vm.prank(policyAdmin);
        policyRegistry.activatePolicy(policyHash);

        assertTrue(policyRegistry.isPolicyActive(policyHash));
        assertEq(
            uint8(policyRegistry.getPolicyStatus(policyHash)),
            uint8(GovProvTypes.PolicyStatus.ACTIVE)
        );
    }

    function testActivePolicyLookupReturnsCurrentPolicyForScope() public {
        _registerAndActivate(policyHash, bytes32(0), metadataHash);

        assertEq(policyRegistry.getActivePolicy(scopeHash), policyHash);
    }

    function testActivatingSuccessorSupersedesPreviousActivePolicyForSameScope() public {
        _registerAndActivate(policyHash, bytes32(0), metadataHash);
        _registerPolicy(policyHashV2, policyHash, metadataHashV2, scopeHash);

        vm.expectEmit(true, true, true, true, address(policyRegistry));
        emit PolicySuperseded(policyHash, policyHashV2, scopeHash, policyAdmin);
        vm.expectEmit(true, true, false, true, address(policyRegistry));
        emit PolicyActivated(policyHashV2, scopeHash, policyAdmin);

        vm.prank(policyAdmin);
        policyRegistry.activatePolicy(policyHashV2);

        assertFalse(policyRegistry.isPolicyActive(policyHash));
        assertTrue(policyRegistry.isPolicyActive(policyHashV2));
        assertEq(policyRegistry.getActivePolicy(scopeHash), policyHashV2);
        assertEq(
            uint8(policyRegistry.getPolicyStatus(policyHash)),
            uint8(GovProvTypes.PolicyStatus.SUPERSEDED)
        );

        GovProvTypes.PolicyRecord memory supersededPolicy = policyRegistry.getPolicy(policyHash);
        assertEq(supersededPolicy.supersededByPolicyHash, policyHashV2);
    }

    function testPolicyAdminCanRevokePolicy() public {
        _registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);

        vm.expectEmit(true, false, false, true, address(policyRegistry));
        emit PolicyRevoked(policyHash, reasonHash, policyAdmin);

        vm.prank(policyAdmin);
        policyRegistry.revokePolicy(policyHash, reasonHash);

        assertEq(
            uint8(policyRegistry.getPolicyStatus(policyHash)),
            uint8(GovProvTypes.PolicyStatus.REVOKED)
        );
    }

    function testRevokedPolicyIsNotActive() public {
        _registerAndActivate(policyHash, bytes32(0), metadataHash);

        vm.prank(policyAdmin);
        policyRegistry.revokePolicy(policyHash, reasonHash);

        assertFalse(policyRegistry.isPolicyActive(policyHash));
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.NoActivePolicy.selector, scopeHash));
        policyRegistry.getActivePolicy(scopeHash);
    }

    function testRevokedPolicyCannotBeActivated() public {
        _registerPolicy(policyHash, bytes32(0), metadataHash, scopeHash);
        vm.prank(policyAdmin);
        policyRegistry.revokePolicy(policyHash, reasonHash);

        vm.prank(policyAdmin);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.PolicyRevoked.selector, policyHash));
        policyRegistry.activatePolicy(policyHash);
    }

    function testSupersededPolicyCannotBeReactivated() public {
        _registerAndActivate(policyHash, bytes32(0), metadataHash);
        _registerAndActivate(policyHashV2, policyHash, metadataHashV2);

        vm.prank(policyAdmin);
        vm.expectRevert(GovProvErrors.InvalidStatusTransition.selector);
        policyRegistry.activatePolicy(policyHash);
    }

    function _registerActor(address actor, string memory actorId) private {
        vm.prank(governanceAdmin);
        actorRegistry.registerActor(
            actor,
            keccak256(bytes(actorId)),
            GovProvTypes.ActorType.HUMAN,
            keccak256(abi.encodePacked("metadata:", actorId))
        );
    }

    function _registerPolicy(
        bytes32 targetPolicyHash,
        bytes32 parentPolicyHash,
        bytes32 targetMetadataHash,
        bytes32 targetScopeHash
    ) private {
        vm.prank(policyAdmin);
        policyRegistry.registerPolicy(
            targetPolicyHash, parentPolicyHash, targetMetadataHash, targetScopeHash
        );
    }

    function _registerAndActivate(
        bytes32 targetPolicyHash,
        bytes32 parentPolicyHash,
        bytes32 targetMetadataHash
    ) private {
        _registerPolicy(targetPolicyHash, parentPolicyHash, targetMetadataHash, scopeHash);
        vm.prank(policyAdmin);
        policyRegistry.activatePolicy(targetPolicyHash);
    }
}
