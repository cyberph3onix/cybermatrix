// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ThreatRegistry} from "../src/ThreatRegistry.sol";

/// @notice Deploys ThreatRegistry. The deployer becomes owner and validator.
///         The relayer (RELAYER_PRIVATE_KEY) gets no on-chain role: it only calls submitReport.
/// forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
contract Deploy is Script {
    function run() external returns (ThreatRegistry registry) {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);
        registry = new ThreatRegistry();
        registry.addValidator(deployer);
        vm.stopBroadcast();

        console2.log("ThreatRegistry deployed at", address(registry));
        console2.log("owner + validator", deployer);
    }
}
