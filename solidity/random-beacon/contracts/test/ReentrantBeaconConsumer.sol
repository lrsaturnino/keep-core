// SPDX-License-Identifier: GPL-3.0-only

pragma solidity 0.8.17;

import "../api/IRandomBeaconConsumer.sol";
import "../RandomBeacon.sol";

// Malicious IRandomBeaconConsumer used in F-09 regression tests.
// When invoked via the callback path, attempts to re-enter
// RandomBeacon.submitRelayEntry(bytes). The nonReentrant modifier on
// submitRelayEntry must revert that re-entry with the ReentrantCall custom
// error. To avoid a false-positive where an unrelated revert (e.g. invalid
// payload, signature validation) is mistaken for the reentrancy guard
// firing, we discriminate on the revert reason: only a 4-byte revert
// matching the ReentrantCall selector flips `reentryRejected`. Any other
// revert leaves `reentryRejected = false` and the test fails.
contract ReentrantBeaconConsumer is IRandomBeaconConsumer {
    RandomBeacon public randomBeacon;
    bool public reentryAttempted;
    bool public reentryRejected;
    bytes public lastRevertReason;

    constructor(RandomBeacon _randomBeacon) {
        randomBeacon = _randomBeacon;
    }

    function __beaconCallback(uint256, uint256) external override {
        reentryAttempted = true;

        // The nonReentrant modifier runs before any other check, so it fires
        // first on the re-entrant call regardless of the payload contents.
        // Any OTHER revert reason means we left the guard path -- e.g. the
        // modifier was removed and we hit signature/state validation.
        try randomBeacon.submitRelayEntry(hex"") {
            // Re-entry succeeded -- the F-09 reentrancy guard is missing.
            // Leave reentryRejected = false; the test will fail.
        } catch (bytes memory reason) {
            lastRevertReason = reason;
            // ReentrantCall is `error ReentrantCall();` (no args), so the
            // revert data is exactly the 4-byte selector.
            if (reason.length == 4) {
                bytes4 selector;
                // Read the first 4 bytes of the dynamic bytes array.
                // bytes memory layout: [32-byte length][data...].
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    selector := mload(add(reason, 32))
                }
                if (selector == RandomBeacon.ReentrantCall.selector) {
                    reentryRejected = true;
                }
            }
        }
    }
}
