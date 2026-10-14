// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { GovProvErrors } from "../src/lib/GovProvErrors.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract ProvenanceRegistryTest is Test {
    ActorRegistry private actorRegistry;
    PolicyRegistry private policyRegistry;
    ProvenanceRegistry private provenanceRegistry;

    address private governanceAdmin = address(0xA11CE);
    address private policyAdmin = address(0xBEEF);
    address private ledgerWriter = address(0x1ED9E);
    address private nonLedgerWriter = address(0xCAFE);
    address private attestationActor = address(0xA100);
    address private unregisteredActor = address(0xBAD);

    bytes32 private policyHash = keccak256("policy:v1");
    bytes32 private policyMetadataHash = keccak256("metadata:policy:v1");
    bytes32 private attestationHash = keccak256("attestation:action:001");
    bytes32 private attestationTypeHash = keccak256("ACTION_PROPOSAL_ATTESTATION");
    bytes32 private subjectHash = keccak256("action:001");
    bytes32 private parentRoot = keccak256("parent:root:001");
    bytes32 private metadataHash = keccak256("metadata:attestation:action:001");
    bytes32 private scopeHash = keccak256("scope:runbook_update");
    bytes32 private reasonHash = keccak256("reason:test");

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

    function setUp() public {
        vm.prank(governanceAdmin);
        actorRegistry = new ActorRegistry(governanceAdmin);
        policyRegistry = new PolicyRegistry(actorRegistry);
        provenanceRegistry = new ProvenanceRegistry(actorRegistry, policyRegistry);

        _registerActor(policyAdmin, "actor:policy-admin", GovProvTypes.ActorType.HUMAN);
        _registerActor(ledgerWriter, "actor:ledger-writer", GovProvTypes.ActorType.SERVICE);
        _registerActor(nonLedgerWriter, "actor:non-ledger-writer", GovProvTypes.ActorType.SERVICE);
        _registerActor(attestationActor, "actor:agent-alpha", GovProvTypes.ActorType.AGENT);

        vm.startPrank(governanceAdmin);
        actorRegistry.grantGovRole(policyAdmin, GovProvRoles.POLICY_ADMIN_ROLE);
        actorRegistry.grantGovRole(ledgerWriter, GovProvRoles.LEDGER_WRITER_ROLE);
        vm.stopPrank();

        vm.prank(policyAdmin);
        policyRegistry.registerPolicy(policyHash, bytes32(0), policyMetadataHash, scopeHash);
    }

    function testConstructorRejectsZeroActorRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new ProvenanceRegistry(ActorRegistry(address(0)), policyRegistry);
    }

    function testConstructorRejectsZeroPolicyRegistry() public {
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        new ProvenanceRegistry(actorRegistry, PolicyRegistry(address(0)));
    }

    function testLedgerWriterCanAnchorAttestation() public {
        vm.expectEmit(true, true, true, true, address(provenanceRegistry));
        emit AttestationAnchored(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash,
            ledgerWriter
        );

        _anchorAttestation(attestationHash, policyHash, attestationActor);

        assertTrue(provenanceRegistry.attestationExists(attestationHash));

        GovProvTypes.AttestationRecord memory record =
            provenanceRegistry.getAttestation(attestationHash);
        assertEq(record.attestationHash, attestationHash);
        assertEq(record.attestationTypeHash, attestationTypeHash);
        assertEq(record.subjectHash, subjectHash);
        assertEq(record.actor, attestationActor);
        assertEq(record.policyHash, policyHash);
        assertEq(record.parentRoot, parentRoot);
        assertEq(record.metadataHash, metadataHash);
        assertEq(record.scopeHash, scopeHash);
        assertTrue(record.exists);
    }

    function testNonLedgerWriterCannotAnchorAttestation() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.MissingRole.selector, nonLedgerWriter, GovProvRoles.LEDGER_WRITER_ROLE
            )
        );
        _anchorAttestationAs(nonLedgerWriter, attestationHash, policyHash, attestationActor);
    }

    function testInactiveLedgerWriterCannotAnchorAttestation() public {
        vm.prank(governanceAdmin);
        actorRegistry.suspendActor(ledgerWriter, reasonHash);

        vm.prank(ledgerWriter);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, ledgerWriter));
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testDuplicateAttestationHashReverts() public {
        _anchorAttestation(attestationHash, policyHash, attestationActor);

        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.AttestationAlreadyAnchored.selector, attestationHash
            )
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testZeroAttestationHashReverts() public {
        vm.prank(ledgerWriter);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "attestationHash"));
        provenanceRegistry.anchorAttestation(
            bytes32(0),
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testZeroAttestationTypeHashReverts() public {
        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "attestationTypeHash")
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            bytes32(0),
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testZeroSubjectHashReverts() public {
        vm.prank(ledgerWriter);
        vm.expectRevert(abi.encodeWithSelector(GovProvErrors.ZeroHash.selector, "subjectHash"));
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            bytes32(0),
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testZeroHeaderActorReverts() public {
        vm.prank(ledgerWriter);
        vm.expectRevert(GovProvErrors.ZeroAddress.selector);
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            address(0),
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testUnregisteredActorInHeaderReverts() public {
        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ActorNotRegistered.selector, unregisteredActor)
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            unregisteredActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testSuspendedActorInHeaderReverts() public {
        vm.prank(governanceAdmin);
        actorRegistry.suspendActor(attestationActor, reasonHash);

        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, attestationActor)
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testRevokedActorInHeaderReverts() public {
        vm.prank(governanceAdmin);
        actorRegistry.revokeActor(attestationActor, reasonHash);

        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.ActorNotActive.selector, attestationActor)
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            policyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testUnknownPolicyHashRevertsWhenPolicyHashIsNonzero() public {
        bytes32 unknownPolicyHash = keccak256("policy:unknown");

        vm.prank(ledgerWriter);
        vm.expectRevert(
            abi.encodeWithSelector(GovProvErrors.PolicyNotFound.selector, unknownPolicyHash)
        );
        provenanceRegistry.anchorAttestation(
            attestationHash,
            attestationTypeHash,
            subjectHash,
            attestationActor,
            unknownPolicyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }

    function testZeroPolicyHashIsAccepted() public {
        _anchorAttestation(attestationHash, bytes32(0), attestationActor);

        assertTrue(provenanceRegistry.attestationExists(attestationHash));
        assertEq(provenanceRegistry.getAttestationPolicy(attestationHash), bytes32(0));
    }

    function testAttestationFieldLookupsWork() public {
        _anchorAttestation(attestationHash, policyHash, attestationActor);

        assertEq(provenanceRegistry.getAttestationActor(attestationHash), attestationActor);
        assertEq(provenanceRegistry.getAttestationPolicy(attestationHash), policyHash);
        assertEq(provenanceRegistry.getAttestationType(attestationHash), attestationTypeHash);
    }

    function testMissingAttestationLookupReverts() public {
        bytes32 missingAttestationHash = keccak256("attestation:missing");

        vm.expectRevert(
            abi.encodeWithSelector(
                GovProvErrors.AttestationNotFound.selector, missingAttestationHash
            )
        );
        provenanceRegistry.getAttestation(missingAttestationHash);
    }

    function testAttestationTypeConstantsUseStableNames() public view {
        assertEq(provenanceRegistry.OBSERVATION_ATTESTATION(), keccak256("OBSERVATION_ATTESTATION"));
        assertEq(
            provenanceRegistry.POLICY_DECISION_ATTESTATION(),
            keccak256("POLICY_DECISION_ATTESTATION")
        );
        assertEq(provenanceRegistry.DEPLOYMENT_ATTESTATION(), keccak256("DEPLOYMENT_ATTESTATION"));
    }

    function _registerActor(address actor, string memory actorId, GovProvTypes.ActorType actorType)
        private
    {
        vm.prank(governanceAdmin);
        actorRegistry.registerActor(
            actor,
            keccak256(bytes(actorId)),
            actorType,
            keccak256(abi.encodePacked("metadata:", actorId))
        );
    }

    function _anchorAttestation(
        bytes32 targetAttestationHash,
        bytes32 targetPolicyHash,
        address targetActor
    ) private {
        _anchorAttestationAs(ledgerWriter, targetAttestationHash, targetPolicyHash, targetActor);
    }

    function _anchorAttestationAs(
        address caller,
        bytes32 targetAttestationHash,
        bytes32 targetPolicyHash,
        address targetActor
    ) private {
        vm.prank(caller);
        provenanceRegistry.anchorAttestation(
            targetAttestationHash,
            attestationTypeHash,
            subjectHash,
            targetActor,
            targetPolicyHash,
            parentRoot,
            metadataHash,
            scopeHash
        );
    }
}
