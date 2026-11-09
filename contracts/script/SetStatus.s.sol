// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ThreatRegistry} from "../src/ThreatRegistry.sol";

/// @notice Validator marks a report Validated or Rejected (demo helper).
/// REPORT_ID=1 STATUS=validated forge script script/SetStatus.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
/// Signs with DEPLOYER_PRIVATE_KEY (the validator). STATUS is "validated" or "rejected".
/// Equivalent cast command (2 = Validated, 3 = Rejected):
///   cast send $REGISTRY_ADDRESS "setStatus(uint256,uint8)" 1 2 --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_PRIVATE_KEY
contract SetStatus is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        ThreatRegistry registry = ThreatRegistry(vm.envAddress("REGISTRY_ADDRESS"));
        uint256 id = vm.envUint("REPORT_ID");
        bytes32 s = keccak256(bytes(vm.envString("STATUS")));

        ThreatRegistry.Status status;
        if (s == keccak256("validated")) status = ThreatRegistry.Status.Validated;
        else if (s == keccak256("rejected")) status = ThreatRegistry.Status.Rejected;
        else revert("STATUS must be 'validated' or 'rejected'");

        vm.startBroadcast(pk);
        registry.setStatus(id, status);
        vm.stopBroadcast();

        console2.log("report", id, "status set to", uint8(status));
    }
}
