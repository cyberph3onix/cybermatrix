// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ThreatRegistry} from "../src/ThreatRegistry.sol";

/// @notice Deploys ThreatRegistry. The deployer becomes owner and validator. The relayer becomes the only reporter
///         (the only address allowed to call submitReport); it has no other role.
///         Relayer address: RELAYER_ADDRESS, or derived locally from RELAYER_PRIVATE_KEY.
/// forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
contract Deploy is Script {
    function run() external returns (ThreatRegistry registry) {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer == address(0)) relayer = vm.addr(vm.envUint("RELAYER_PRIVATE_KEY"));
        require(relayer != deployer, "relayer must differ from deployer");

        // A dispute posts this bond (wei); returned if the validator upholds it, forfeited if not.
        uint96 bond = uint96(vm.envOr("DISPUTE_BOND_WEI", uint256(0.001 ether)));

        vm.startBroadcast(pk);
        registry = new ThreatRegistry();
        registry.addValidator(deployer);
        registry.setDisputeBond(bond);
        registry.addReporter(relayer);
        vm.stopBroadcast();

        console2.log("ThreatRegistry deployed at", address(registry));
        console2.log("owner + validator", deployer);
        console2.log("reporter (relayer)", relayer);
        console2.log("dispute bond (wei)", uint256(bond));
    }
}
