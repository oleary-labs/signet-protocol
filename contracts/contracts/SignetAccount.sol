// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IAccount, PackedUserOperation} from "./interfaces/IAccount.sol";
import {FROSTVerifier} from "./FROSTVerifier.sol";

/// @title SignetAccount
/// @notice ERC-4337 smart account that validates operations using FROST threshold Schnorr
/// signatures (RFC 9591). The account stores the 33-byte compressed group public key and
/// derives the signer address from it.
///
/// Usage with ERC-4337:
/// 1. Deploy via factory with entryPoint and groupPublicKey
/// 2. The FROST signing group produces a Schnorr signature on the userOpHash
/// 3. The signature (65 bytes: R.x || z || v) is placed in userOp.signature
/// 4. EntryPoint calls validateUserOp, which verifies via RFC 9591 challenge + ecrecover
///
/// @dev Minimal reference implementation for research.
contract SignetAccount is IAccount {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice The ERC-4337 EntryPoint that may call validateUserOp.
    address public immutable entryPoint;

    /// @notice The signer address: keccak256(uncompressed group public key)[12:].
    address public signer;

    /// @notice The 33-byte compressed secp256k1 group public key.
    /// Required for RFC 9591 challenge computation.
    bytes public groupPublicKey;

    error OnlyEntryPoint();
    error OnlySelf();

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert OnlyEntryPoint();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    constructor(address _entryPoint, bytes memory _groupPublicKey, address _signer) {
        entryPoint = _entryPoint;
        groupPublicKey = _groupPublicKey;
        signer = _signer;
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /// @notice Execute a call. Only callable by EntryPoint.
    function execute(address dest, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = dest.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @notice Rotate the signer. Only callable by the account itself (via execute).
    function rotateSigner(bytes memory newGroupPublicKey, address newSigner) external onlySelf {
        groupPublicKey = newGroupPublicKey;
        signer = newSigner;
    }

    /// @dev Validate the FROST Schnorr signature in the user operation.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        // FROST signs the raw message bytes (the 32-byte userOpHash).
        if (FROSTVerifier.verify(abi.encodePacked(userOpHash), userOp.signature, groupPublicKey, signer)) {
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @dev Pay the EntryPoint the required prefund.
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
    }

    receive() external payable {}
}
