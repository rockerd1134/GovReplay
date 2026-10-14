// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { HardenedProvenanceRegistry } from "../src/HardenedProvenanceRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract HardenedProvenanceRegistryTest is Test {
    ActorRegistry private actors;
    PolicyRegistry private policies;
    HardenedProvenanceRegistry private provenance;
    address private admin = address(0xA11CE);
    address private writer = address(0xBEEF);
    address private actor = address(0xCAFE);
    bytes32 private actionType = keccak256("ACTION_PROPOSAL_ATTESTATION");
    bytes32 private approvalType = keccak256("APPROVAL_ATTESTATION");
    bytes32 private action = keccak256("hardened:action");

    function setUp() public {
        vm.prank(admin);
        actors = new ActorRegistry(admin);
        policies = new PolicyRegistry(actors);
        provenance = new HardenedProvenanceRegistry(actors, policies);
        vm.startPrank(admin);
        actors.registerActor(writer, keccak256("writer"), GovProvTypes.ActorType.SERVICE, bytes32(0));
        actors.registerActor(actor, keccak256("actor"), GovProvTypes.ActorType.AGENT, bytes32(0));
        actors.grantGovRole(writer, GovProvRoles.LEDGER_WRITER_ROLE);
        vm.stopPrank();
    }

    function _anchor(bytes32 kind, bytes32 hash, address sender) private {
        vm.prank(sender);
        provenance.anchorAttestation(hash, kind, keccak256("subject"), actor,
            bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function testActiveDeployerAcceptedAtN() public {
        vm.prank(admin);
        actors.grantGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        _anchor(actionType, action, writer);
        assertTrue(provenance.attestationExists(action));
    }

    function testActiveActorWithoutDeployerRejectedAtN() public {
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.MissingRole.selector,
            actor, GovProvRoles.DEPLOYER_ROLE));
        _anchor(actionType, action, writer);
        assertFalse(provenance.attestationExists(action));
    }

    function testRevokedRoleRejectedAndRegrantAccepted() public {
        vm.startPrank(admin);
        actors.grantGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        actors.revokeGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.MissingRole.selector,
            actor, GovProvRoles.DEPLOYER_ROLE));
        _anchor(actionType, action, writer);
        vm.prank(admin);
        actors.grantGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        _anchor(actionType, action, writer);
        assertTrue(provenance.attestationExists(action));
    }

    function testInactiveActorRejected() public {
        vm.startPrank(admin);
        actors.grantGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        actors.suspendActor(actor, keccak256("reason"));
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.MissingRole.selector,
            actor, GovProvRoles.DEPLOYER_ROLE));
        _anchor(actionType, action, writer);
    }

    function testWriterAuthorizationStillRequired() public {
        vm.prank(admin);
        actors.grantGovRole(actor, GovProvRoles.DEPLOYER_ROLE);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotRegistered.selector,
            address(0x1234)));
        _anchor(actionType, action, address(0x1234));
    }

    function testOtherAttestationTypeKeepsBaseRule() public {
        _anchor(approvalType, keccak256("approval"), writer);
        assertTrue(provenance.attestationExists(keccak256("approval")));
    }
}
