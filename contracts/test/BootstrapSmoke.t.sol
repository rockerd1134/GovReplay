// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";
import { BootstrapSmoke } from "../src/BootstrapSmoke.sol";

contract BootstrapSmokeTest is Test {
    BootstrapSmoke private smoke;

    address private governanceAdmin = address(0xA11CE);

    function setUp() public {
        smoke = new BootstrapSmoke(governanceAdmin);
    }

    function testBootstrapReady() public view {
        assertTrue(smoke.bootstrapReady());
        assertEq(smoke.PROJECT(), "GovReplay");
    }

    function testOpenZeppelinAccessControlIsAvailable() public view {
        assertTrue(smoke.hasRole(smoke.DEFAULT_ADMIN_ROLE(), governanceAdmin));
        assertTrue(smoke.hasRole(smoke.GOVERNANCE_ADMIN_ROLE(), governanceAdmin));
    }
}
