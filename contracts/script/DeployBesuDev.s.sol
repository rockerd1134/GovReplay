// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the public release: use the supplied disposable administrator wallet.
pragma solidity 0.8.26;

import { Script } from "forge-std/Script.sol";
import { ActorRegistry } from "../src/ActorRegistry.sol";
import { ApprovalRegistry } from "../src/ApprovalRegistry.sol";
import { ContractDirectory } from "../src/ContractDirectory.sol";
import { DeploymentRegistry } from "../src/DeploymentRegistry.sol";
import { PolicyRegistry } from "../src/PolicyRegistry.sol";
import { ProvenanceRegistry } from "../src/ProvenanceRegistry.sol";
import { HardenedProvenanceRegistry } from "../src/HardenedProvenanceRegistry.sol";
import { GovProvRoles } from "../src/lib/GovProvRoles.sol";
import { GovProvTypes } from "../src/lib/GovProvTypes.sol";

contract DeployBesuDev is Script {
    address private GOVERNANCE_ADMIN;
    address private constant LEDGER_WRITER = 0x627306090abaB3A6e1400e9345bC60c78a8BEf57;
    address private constant DEPLOYER = 0xf17f52151EbEF6C7334FAD080c5704D77216b732;

    bytes32 private constant DEFAULT_SCOPE = keccak256("scope:default");
    bytes32 private constant DELIVERY_POLICY_V1 = keccak256("govprov:policy:delivery-v1");

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("GOVPROV_DEV_DEPLOYER_PRIVATE_KEY");
        string memory manifestPath =
            vm.envOr("GOVPROV_DEPLOYMENT_MANIFEST", string("../runs/besu-dev/ledger/deployment_manifest.json"));

        GOVERNANCE_ADMIN = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        ActorRegistry actorRegistry = new ActorRegistry(GOVERNANCE_ADMIN);
        PolicyRegistry policyRegistry = new PolicyRegistry(actorRegistry);
        ProvenanceRegistry provenanceRegistry = vm.envOr("GOVPROV_HARDENED_PROVENANCE", false)
            ? new HardenedProvenanceRegistry(actorRegistry, policyRegistry)
            : new ProvenanceRegistry(actorRegistry, policyRegistry);
        ApprovalRegistry approvalRegistry = new ApprovalRegistry(actorRegistry, provenanceRegistry);
        DeploymentRegistry deploymentRegistry =
            new DeploymentRegistry(actorRegistry, policyRegistry, provenanceRegistry, approvalRegistry);
        ContractDirectory contractDirectory = new ContractDirectory(actorRegistry);

        _bootstrapActors(actorRegistry);
        _bootstrapPolicy(policyRegistry);
        address[] memory deployedContracts = new address[](6);
        deployedContracts[0] = address(actorRegistry);
        deployedContracts[1] = address(policyRegistry);
        deployedContracts[2] = address(provenanceRegistry);
        deployedContracts[3] = address(approvalRegistry);
        deployedContracts[4] = address(deploymentRegistry);
        deployedContracts[5] = address(contractDirectory);

        string memory contractSetLabel =
            vm.envOr("GOVPROV_DEPLOYMENT_CONTRACT_SET_LABEL", string("govprov:contract-set:besu-dev:v1"));
        bytes32 contractSetId =
            _bootstrapContractDirectory(contractDirectory, deployedContracts, contractSetLabel);

        vm.stopBroadcast();

        _writeManifest(manifestPath, contractSetId, deployedContracts);
    }

    function _bootstrapActors(ActorRegistry actorRegistry) private {
        actorRegistry.grantGovRole(GOVERNANCE_ADMIN, GovProvRoles.POLICY_ADMIN_ROLE);
        actorRegistry.grantGovRole(GOVERNANCE_ADMIN, GovProvRoles.LEDGER_WRITER_ROLE);
        actorRegistry.grantGovRole(GOVERNANCE_ADMIN, GovProvRoles.DEPLOYER_ROLE);
        actorRegistry.grantGovRole(GOVERNANCE_ADMIN, GovProvRoles.APPROVER_ROLE);

        actorRegistry.registerActor(
            LEDGER_WRITER,
            keccak256("govprov:actor:ledger-writer"),
            GovProvTypes.ActorType.SERVICE,
            keccak256("govprov:actor:ledger-writer:metadata")
        );
        actorRegistry.registerActor(
            DEPLOYER,
            keccak256("govprov:actor:deployer"),
            GovProvTypes.ActorType.HUMAN,
            keccak256("govprov:actor:deployer:metadata")
        );

        actorRegistry.grantGovRole(LEDGER_WRITER, GovProvRoles.LEDGER_WRITER_ROLE);
        actorRegistry.grantGovRole(DEPLOYER, GovProvRoles.DEPLOYER_ROLE);
    }

    function _bootstrapPolicy(PolicyRegistry policyRegistry) private {
        policyRegistry.registerPolicy(
            DELIVERY_POLICY_V1,
            bytes32(0),
            keccak256("govprov:policy:delivery-v1:metadata"),
            DEFAULT_SCOPE
        );
        policyRegistry.activatePolicy(DELIVERY_POLICY_V1);
    }

    function _bootstrapContractDirectory(
        ContractDirectory contractDirectory,
        address[] memory contractAddresses,
        string memory contractSetLabel
    ) private returns (bytes32) {
        bytes32[] memory names = _contractNameHashes();

        for (uint256 i = 0; i < names.length; i++) {
            contractDirectory.registerContract(
                names[i],
                contractAddresses[i],
                keccak256(abi.encodePacked("govprov:contract-version:v1:", names[i], contractAddresses[i])),
                keccak256(abi.encodePacked("govprov:contract-source:v1:", names[i])),
                keccak256(abi.encodePacked("govprov:contract-abi:v1:", names[i])),
                keccak256(abi.encodePacked("govprov:contract-metadata:v1:", names[i], contractAddresses[i]))
            );
        }

        bytes32 contractSetId = keccak256(abi.encodePacked(contractSetLabel, contractAddresses));
        contractDirectory.activateContractSet(
            contractSetId, keccak256(abi.encodePacked(contractSetLabel, ":metadata")), names, contractAddresses
        );
        return contractSetId;
    }

    function _writeManifest(
        string memory manifestPath,
        bytes32 contractSetId,
        address[] memory contractAddresses
    ) private {
        vm.writeFile(manifestPath, _manifestJson(contractSetId, contractAddresses));
    }

    function _manifestJson(
        bytes32 contractSetId,
        address[] memory contractAddresses
    ) private view returns (string memory) {
        uint256 chainId = vm.envOr("GOVPROV_DEPLOYMENT_CHAIN_ID", uint256(1337));
        string memory network = vm.envOr("GOVPROV_DEPLOYMENT_NETWORK", string("besu-local-dev"));
        string memory genesisLabel =
            vm.envOr("GOVPROV_DEPLOYMENT_GENESIS_LABEL", string("besu-dev-network-genesis"));
        string memory rpcEndpoint =
            vm.envOr("GOVPROV_DEPLOYMENT_RPC_ENDPOINT", string("http://besu-dev:8545"));

        return string.concat(
            "{",
            "\"schema_version\":\"govprov.contract-addresses.v1\",",
            "\"chain\":{\"chain_id\":",
            vm.toString(chainId),
            ",\"network\":\"",
            network,
            "\",\"genesis_hash\":\"",
            vm.toString(keccak256(bytes(genesisLabel))),
            "\",\"rpc_endpoint_hash\":\"",
            vm.toString(keccak256(bytes(rpcEndpoint))),
            "\"},",
            "\"build\":{\"generated_at\":\"1970-01-01T00:00:00Z\",\"tool\":\"forge script DeployBesuDev\",\"solc_version\":\"0.8.26\",\"manifest_kind\":\"deployment\"},",
            "\"contract_set_id\":\"",
            vm.toString(contractSetId),
            "\",",
            "\"governance_admin\":{\"address\":\"",
            vm.toString(GOVERNANCE_ADMIN),
            "\",\"actor_id_hash\":\"",
            vm.toString(keccak256("govprov:bootstrap-governance-admin")),
            "\"},",
            "\"active_scopes\":[{\"scope_hash\":\"",
            vm.toString(DEFAULT_SCOPE),
            "\",\"metadata_hash\":\"",
            vm.toString(keccak256("govprov:scope:default:metadata")),
            "\"}],",
            "\"active_policies\":[{\"scope_hash\":\"",
            vm.toString(DEFAULT_SCOPE),
            "\",\"policy_hash\":\"",
            vm.toString(DELIVERY_POLICY_V1),
            "\",\"metadata_hash\":\"",
            vm.toString(keccak256("govprov:policy:delivery-v1:metadata")),
            "\"}],",
            "\"contracts\":",
            _contractsJson(contractAddresses),
            "}"
        );
    }

    function _contractsJson(address[] memory contractAddresses) private pure returns (string memory) {
        return string.concat(
            "{",
            _contractJson("ActorRegistry", contractAddresses[0], "src/ActorRegistry.sol"),
            ",",
            _contractJson("PolicyRegistry", contractAddresses[1], "src/PolicyRegistry.sol"),
            ",",
            _contractJson("ProvenanceRegistry", contractAddresses[2], "src/ProvenanceRegistry.sol"),
            ",",
            _contractJson("ApprovalRegistry", contractAddresses[3], "src/ApprovalRegistry.sol"),
            ",",
            _contractJson("DeploymentRegistry", contractAddresses[4], "src/DeploymentRegistry.sol"),
            ",",
            _contractJson("ContractDirectory", contractAddresses[5], "src/ContractDirectory.sol"),
            "}"
        );
    }

    function _contractJson(
        string memory name,
        address contractAddress,
        string memory sourcePath
    ) private pure returns (string memory) {
        bytes32 nameHash = keccak256(abi.encodePacked("govprov:contract:", name));
        bytes32 sourceHash = keccak256(abi.encodePacked("govprov:contract-source:v1:", nameHash));
        bytes32 abiHash = keccak256(abi.encodePacked("govprov:contract-abi:v1:", nameHash));
        bytes32 versionHash =
            keccak256(abi.encodePacked("govprov:contract-version:v1:", nameHash, contractAddress));
        bytes32 metadataHash =
            keccak256(abi.encodePacked("govprov:contract-metadata:v1:", nameHash, contractAddress));

        return string.concat(
            "\"",
            name,
            "\":{\"address\":\"",
            vm.toString(contractAddress),
            "\",\"name_hash\":\"",
            vm.toString(nameHash),
            "\",\"version_hash\":\"",
            vm.toString(versionHash),
            "\",\"source_hash\":\"",
            vm.toString(sourceHash),
            "\",\"abi_hash\":\"",
            vm.toString(abiHash),
            "\",\"metadata_hash\":\"",
            vm.toString(metadataHash),
            "\",\"source_path_hash\":\"",
            vm.toString(keccak256(bytes(sourcePath))),
            "\"}"
        );
    }

    function _contractNameHashes() private pure returns (bytes32[] memory) {
        bytes32[] memory names = new bytes32[](6);
        names[0] = keccak256("govprov:contract:ActorRegistry");
        names[1] = keccak256("govprov:contract:PolicyRegistry");
        names[2] = keccak256("govprov:contract:ProvenanceRegistry");
        names[3] = keccak256("govprov:contract:ApprovalRegistry");
        names[4] = keccak256("govprov:contract:DeploymentRegistry");
        names[5] = keccak256("govprov:contract:ContractDirectory");
        return names;
    }

}
