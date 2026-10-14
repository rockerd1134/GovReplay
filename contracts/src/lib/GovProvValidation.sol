// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rocker D'Antonio.
// Modified for the Apache-2.0 public release; contract behavior is unchanged.
pragma solidity 0.8.26;

import { GovProvErrors } from "./GovProvErrors.sol";

library GovProvValidation {
    function requireNonZeroAddress(address value) internal pure {
        if (value == address(0)) {
            revert GovProvErrors.ZeroAddress();
        }
    }

    function requireNonZeroHash(bytes32 value, string memory field) internal pure {
        if (value == bytes32(0)) {
            revert GovProvErrors.ZeroHash(field);
        }
    }
}
