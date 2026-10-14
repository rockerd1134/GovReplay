// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { GovProvRoles } from "./lib/GovProvRoles.sol";

contract BootstrapSmoke is AccessControl {
    bytes32 public constant GOVERNANCE_ADMIN_ROLE = GovProvRoles.GOVERNANCE_ADMIN_ROLE;

    string public constant PROJECT = "GovReplay";

    constructor(address governanceAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, governanceAdmin);
        _grantRole(GOVERNANCE_ADMIN_ROLE, governanceAdmin);
    }

    function bootstrapReady() external pure returns (bool) {
        return true;
    }
}
