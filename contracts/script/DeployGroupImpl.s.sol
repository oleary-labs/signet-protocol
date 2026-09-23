// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

import "../contracts/SignetGroup.sol";

/// @title DeployGroupImpl
/// @notice Deploys a new SignetGroup implementation for a beacon upgrade. It
///         deploys the logic contract and nothing else — it deliberately does
///         NOT point the beacon at it.
///
/// The split follows the trust boundary the deployment already draws. This runs
/// with the hot deploy key, which after `fund` holds no standing power; the
/// beacon upgrade is a single `upgradeGroupImplementation(address)` call that
/// must come from the cold factory owner. Folding both into one broadcast would
/// mean the cold key signing a script whose behaviour it cannot read off the
/// transaction, instead of one call with one argument.
///
/// CREATE2 is what makes that argument checkable. The address is a function of
/// the init code alone, so the cold signer can build this source independently
/// and confirm the address it is about to bless holds the code it expects,
/// without trusting whoever ran the deploy. The script prints the init-code hash
/// for exactly that comparison.
///
/// A consequence worth knowing: deploying identical init code at the same salt
/// twice reverts, because the address is already occupied. That is the check
/// working, not a failure — it means the implementation is already on chain.
/// Bump SALT only to deploy genuinely different code at a fresh address.
///
/// Required environment variables:
///   none
///
/// Optional environment variables:
///   SALT — uint256 CREATE2 salt (default: 0)
///
/// Run (simulate, no broadcast):
///   forge script script/DeployGroupImpl.s.sol --rpc-url <RPC_URL>
///
/// Run (live):
///   forge script script/DeployGroupImpl.s.sol \
///     --rpc-url <RPC_URL> --broadcast --private-key <DEPLOYER_PRIVATE_KEY>
///
/// Prefer `alpha-contracts.sh deploy-group-impl`, which refuses to run this at
/// all until the new layout has been checked against the deployed one.
contract DeployGroupImpl is Script {
    function run() external {
        bytes32 salt = bytes32(vm.envOr("SALT", uint256(0)));

        // Hash the init code before deploying, so the value printed is the one
        // that determined the address rather than a re-derivation of it.
        bytes32 initCodeHash = keccak256(type(SignetGroup).creationCode);

        vm.startBroadcast();
        SignetGroup impl = new SignetGroup{salt: salt}();
        vm.stopBroadcast();

        console2.log("=== SignetGroup implementation ===");
        console2.log("deployer     :", msg.sender);
        console2.log("salt         :", vm.toString(salt));
        console2.log("initCodeHash :", vm.toString(initCodeHash));
        console2.log("groupImpl    :", address(impl));

        // Machine-readable, consumed by alpha-contracts.sh.
        console2.log(string.concat("UPGRADE:groupImpl=", vm.toString(address(impl))));
        console2.log(string.concat("UPGRADE:initCodeHash=", vm.toString(initCodeHash)));
    }
}
