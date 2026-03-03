// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../contracts/SignetFactory.sol";
import "../contracts/SignetGroup.sol";

/// @title DeployFactory
/// @notice Deploys the SignetGroup implementation, the SignetFactory implementation,
///         and the UUPS proxy that wraps the factory.
///
/// Required environment variables:
///   ADMIN_ADDRESS   — address that will own the factory (and therefore the beacon)
///
/// Optional environment variables:
///   SALT            — bytes32 hex value for CREATE2 deployments (default: 0)
///
/// Run (dry-run, no broadcast):
///   forge script script/DeployFactory.s.sol --rpc-url <RPC_URL>
///
/// Run (live broadcast):
///   forge script script/DeployFactory.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --private-key <DEPLOYER_PRIVATE_KEY>
///
/// With a hardware wallet (Ledger):
///   forge script script/DeployFactory.s.sol \
///     --rpc-url <RPC_URL> \
///     --broadcast \
///     --ledger \
///     --sender <SENDER_ADDRESS>
contract DeployFactory is Script {
    function run() external {
        address admin = vm.envAddress("ADMIN_ADDRESS");

        vm.startBroadcast();

        // 1. Deploy the SignetGroup logic contract (used by the UpgradeableBeacon).
        SignetGroup groupImpl = new SignetGroup();

        // 2. Deploy the SignetFactory logic contract.
        SignetFactory factoryImpl = new SignetFactory();

        // 3. Deploy the UUPS proxy, calling initialize() in the same transaction.
        bytes memory initData = abi.encodeCall(
            SignetFactory.initialize,
            (admin, address(groupImpl))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);

        vm.stopBroadcast();

        // Wrap the proxy as a typed handle for the log output.
        SignetFactory factory = SignetFactory(address(proxy));

        console2.log("=== Signet Factory Deployment ===");
        console2.log("deployer       :", msg.sender);
        console2.log("admin          :", admin);
        console2.log("groupImpl      :", address(groupImpl));
        console2.log("factoryImpl    :", address(factoryImpl));
        console2.log("factory (proxy):", address(proxy));
        console2.log("groupBeacon    :", factory.groupBeacon());

        // Machine-readable lines consumed by devnet/start.sh
        console2.log(string.concat("DEPLOY:factory=",    vm.toString(address(proxy))));
        console2.log(string.concat("DEPLOY:groupImpl=",  vm.toString(address(groupImpl))));
        console2.log(string.concat("DEPLOY:beacon=",     vm.toString(factory.groupBeacon())));
    }
}
