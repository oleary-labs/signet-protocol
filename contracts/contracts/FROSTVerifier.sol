// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title FROSTVerifier
/// @notice Verifies FROST threshold Schnorr signatures (RFC 9591) on secp256k1 using ecrecover.
///
/// The FROST signing protocol produces signatures (R, z) such that:
///   z·G = R + c·Y   where c = H2(R || Y || msg)
///
/// H2 is the RFC 9591 secp256k1-SHA256-v1 challenge hash, computed via
/// expand_message_xmd (RFC 9380) with DST "FROST-secp256k1-SHA256-v1chal".
///
/// The ecrecover trick rearranges the verification equation:
///   ecrecover(hash_ec, v_R+27, rx, s_ec) = address(Y)
/// where:
///   s_ec    = -rx · c⁻¹ mod N
///   hash_ec = -rx · z · c⁻¹ mod N
///
/// @dev Designed as a library for use in ERC-4337 account contracts.
/// Signature format: R.x(32) || z(32) || v(1), where v = R.y parity (0=even, 1=odd).
library FROSTVerifier {
    /// @dev secp256k1 curve order.
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Verify a FROST signature against an expected signer address.
    /// @param message The message bytes that were signed (typically a 32-byte hash).
    /// @param signature 65-byte signature: R.x(32) || z(32) || v(1).
    /// @param groupPublicKey 33-byte compressed secp256k1 group public key.
    /// @param signer Expected signer address: keccak256(uncompressed Y)[12:].
    /// @return True if the signature is valid.
    function verify(
        bytes memory message,
        bytes memory signature,
        bytes memory groupPublicKey,
        address signer
    ) internal view returns (bool) {
        if (signature.length != 65) return false;
        if (groupPublicKey.length != 33) return false;
        if (signer == address(0)) return false;

        uint256 rx;
        uint256 z;
        uint8 v;
        assembly {
            rx := mload(add(signature, 32))
            z  := mload(add(signature, 64))
            v  := byte(0, mload(add(signature, 96)))
        }

        if (rx == 0 || rx >= N) return false;
        if (z == 0 || z >= N) return false;

        // Reconstruct 33-byte compressed R from R.x and v.
        bytes memory rCompressed = new bytes(33);
        rCompressed[0] = v == 0 ? bytes1(0x02) : bytes1(0x03);
        assembly {
            mstore(add(rCompressed, 33), rx)
        }

        // Compute RFC 9591 challenge: c = H2(R_compressed || groupPublicKey || message)
        uint256 c = _frostChallenge(rCompressed, groupPublicKey, message);
        if (c == 0) return false;

        // c_inv = c^(N-2) mod N
        uint256 cInv = _modInverse(c);

        // ecrecover parameters:
        //   s_ec    = -rx · c_inv        mod N
        //   hash_ec = -rx · z · c_inv    mod N
        uint256 sEc    = N - mulmod(rx, cInv, N);
        uint256 hashEc = N - mulmod(mulmod(rx, z, N), cInv, N);

        address recovered = ecrecover(bytes32(hashEc), v + 27, bytes32(rx), bytes32(sEc));
        return recovered == signer && recovered != address(0);
    }

    /// @notice Compute the FROST challenge c = H2(R || PK || msg) per RFC 9591 secp256k1-SHA256-v1.
    /// @dev Uses expand_message_xmd (RFC 9380) with SHA-256, DST="FROST-secp256k1-SHA256-v1chal",
    ///      producing 48 bytes, reduced mod N.
    ///
    /// expand_message_xmd steps (for SHA-256, output_len=48):
    ///   ell = ceil(48/32) = 2
    ///   DST_prime = DST || I2OSP(len(DST), 1)
    ///   b0 = SHA256(Z_pad(64) || input || I2OSP(48, 2) || 0x00 || DST_prime)
    ///   b1 = SHA256(b0 || 0x01 || DST_prime)
    ///   b2 = SHA256(XOR(b1, b0) || 0x02 || DST_prime)
    ///   uniform = b1 || b2[0:16]   (48 bytes total)
    ///   c = int(uniform) mod N
    function _frostChallenge(
        bytes memory rCompressed,
        bytes memory groupPublicKey,
        bytes memory message
    ) private view returns (uint256) {
        // DST = "FROST-secp256k1-SHA256-v1chal" (29 bytes)
        // DST_prime = DST || 0x1d (29 in 1 byte)
        bytes memory dstPrime = "FROST-secp256k1-SHA256-v1chal\x1d";

        // input = R_compressed || groupPublicKey || message
        bytes memory input = abi.encodePacked(rCompressed, groupPublicKey, message);

        // b0 = SHA256(Z_pad(64) || input || I2OSP(48,2) || 0x00 || DST_prime)
        bytes32 b0 = _sha256(abi.encodePacked(
            bytes32(0), bytes32(0),  // Z_pad: 64 zero bytes
            input,
            bytes2(0x0030),          // I2OSP(48, 2) = 0x0030
            bytes1(0x00),
            dstPrime
        ));

        // b1 = SHA256(b0 || 0x01 || DST_prime)
        bytes32 b1 = _sha256(abi.encodePacked(b0, bytes1(0x01), dstPrime));

        // b2 = SHA256(XOR(b1, b0) || 0x02 || DST_prime)
        bytes32 b1XorB0 = b1 ^ b0;
        bytes32 b2 = _sha256(abi.encodePacked(b1XorB0, bytes1(0x02), dstPrime));

        // uniform = b1(32) || b2[0:16] = 48 bytes
        // c = int(uniform) mod N
        // Since uniform is 48 bytes (384 bits), we need to combine b1 (256 bits) and
        // the top 128 bits of b2 into a 384-bit integer, then reduce mod N.
        uint256 b1_uint = uint256(b1);
        uint128 b2_top = uint128(uint256(b2) >> 128);

        // c = (b1_uint * 2^128 + b2_top) mod N
        // Use modexp for this: compute (b1_uint * 2^128) mod N, then add b2_top mod N.
        uint256 b1Shifted = mulmod(b1_uint, 2**128, N);
        uint256 c = addmod(b1Shifted, uint256(b2_top), N);

        return c;
    }

    /// @notice SHA-256 via the precompile at address 0x02.
    function _sha256(bytes memory data) private view returns (bytes32 result) {
        (bool ok, bytes memory output) = address(0x02).staticcall(data);
        require(ok && output.length >= 32, "FROSTVerifier: sha256 failed");
        assembly {
            result := mload(add(output, 32))
        }
    }

    /// @notice Compute a⁻¹ mod N using modexp precompile (Fermat's little theorem).
    function _modInverse(uint256 a) private view returns (uint256 result) {
        bytes memory input = abi.encodePacked(
            uint256(32), uint256(32), uint256(32),
            a, N - 2, N
        );
        (bool ok, bytes memory output) = address(0x05).staticcall(input);
        require(ok && output.length >= 32, "FROSTVerifier: modexp failed");
        assembly {
            result := mload(add(output, 32))
        }
    }
}
