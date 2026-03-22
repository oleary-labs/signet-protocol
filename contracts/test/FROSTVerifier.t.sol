// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {FROSTVerifier} from "../contracts/FROSTVerifier.sol";
import {SignetAccount} from "../contracts/SignetAccount.sol";
import {PackedUserOperation} from "../contracts/interfaces/IAccount.sol";

/// @dev Wrapper to expose the library function for testing.
contract FROSTVerifierHarness {
    function verify(
        bytes memory message,
        bytes memory signature,
        bytes memory groupPublicKey,
        address signer
    ) external view returns (bool) {
        return FROSTVerifier.verify(message, signature, groupPublicKey, signer);
    }
}

contract FROSTVerifierTest is Test {
    FROSTVerifierHarness verifier;

    // Test vector generated from FROST 2-of-3 threshold Schnorr signing (bytemare/frost).
    // Produced by cmd/testvector with parties ["alice","bob","carol"], threshold=2,
    // signers=["alice","bob"], msg=0x0102...1f20.
    bytes constant GROUP_PUB_KEY = hex"023f7604a1c4b0d0d27fa514d44e641e13ccb8f24598e4e702e502026a9ea5c92e";
    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0xaAF830452688305749D3e306eB54095C7411d276;
    bytes32 constant SIG_RX = 0x7d02f48940f10854f148a07fbb86b7af2b6764318772c648fbd37452c290ffd5;
    bytes32 constant SIG_Z = 0x56cc68b7bf192683e1015431da5884788f9280846270c10b00ed7b493b34e790;
    uint8 constant SIG_V = 0;

    function setUp() public {
        verifier = new FROSTVerifierHarness();
    }

    function _sig() internal pure returns (bytes memory) {
        return abi.encodePacked(SIG_RX, SIG_Z, SIG_V);
    }

    function _msg() internal pure returns (bytes memory) {
        return abi.encodePacked(MSG_HASH);
    }

    function testVerifyValid() public view {
        assertTrue(verifier.verify(_msg(), _sig(), GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyWrongSigner() public view {
        assertFalse(verifier.verify(_msg(), _sig(), GROUP_PUB_KEY, address(0xdead)));
    }

    function testVerifyWrongMessage() public view {
        assertFalse(verifier.verify(abi.encodePacked(bytes32(uint256(1))), _sig(), GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyTamperedZ() public view {
        bytes memory sig = abi.encodePacked(SIG_RX, bytes32(uint256(SIG_Z) ^ 1), SIG_V);
        assertFalse(verifier.verify(_msg(), sig, GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyTamperedRx() public view {
        bytes memory sig = abi.encodePacked(bytes32(uint256(SIG_RX) ^ 1), SIG_Z, SIG_V);
        assertFalse(verifier.verify(_msg(), sig, GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyFlippedV() public view {
        uint8 wrongV = SIG_V == 0 ? 1 : 0;
        bytes memory sig = abi.encodePacked(SIG_RX, SIG_Z, wrongV);
        assertFalse(verifier.verify(_msg(), sig, GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyBadLength() public view {
        assertFalse(verifier.verify(_msg(), hex"deadbeef", GROUP_PUB_KEY, SIGNER));
        assertFalse(verifier.verify(_msg(), "", GROUP_PUB_KEY, SIGNER));
    }

    function testVerifyZeroSigner() public view {
        assertFalse(verifier.verify(_msg(), _sig(), GROUP_PUB_KEY, address(0)));
    }

    function testGasCost() public {
        uint256 gasBefore = gasleft();
        verifier.verify(_msg(), _sig(), GROUP_PUB_KEY, SIGNER);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("FROST verify gas", gasUsed);
        // SHA-256 precompile calls + modexp + ecrecover. May be higher than before.
        assertLt(gasUsed, 30_000);
    }
}

contract SignetAccountFROSTTest is Test {
    SignetAccount account;
    address entryPoint;

    bytes constant GROUP_PUB_KEY = hex"023f7604a1c4b0d0d27fa514d44e641e13ccb8f24598e4e702e502026a9ea5c92e";
    bytes32 constant MSG_HASH = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    address constant SIGNER = 0xaAF830452688305749D3e306eB54095C7411d276;
    bytes32 constant SIG_RX = 0x7d02f48940f10854f148a07fbb86b7af2b6764318772c648fbd37452c290ffd5;
    bytes32 constant SIG_Z = 0x56cc68b7bf192683e1015431da5884788f9280846270c10b00ed7b493b34e790;
    uint8 constant SIG_V = 0;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        account = new SignetAccount(entryPoint, GROUP_PUB_KEY, SIGNER);
        vm.deal(address(account), 1 ether);
    }

    function testValidateUserOp_valid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, SIG_V);

        vm.prank(entryPoint);
        uint256 result = account.validateUserOp(userOp, MSG_HASH, 0);
        assertEq(result, 0, "valid signature should return 0");
    }

    function testValidateUserOp_invalid() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, uint8(SIG_V ^ 1));

        vm.prank(entryPoint);
        uint256 result = account.validateUserOp(userOp, MSG_HASH, 0);
        assertEq(result, 1, "invalid signature should return 1");
    }

    function testValidateUserOp_onlyEntryPoint() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        vm.expectRevert(SignetAccount.OnlyEntryPoint.selector);
        account.validateUserOp(userOp, MSG_HASH, 0);
    }

    function testValidateUserOp_paysPrefund() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(SIG_RX, SIG_Z, SIG_V);
        uint256 prefund = 0.01 ether;

        uint256 epBalBefore = entryPoint.balance;
        vm.prank(entryPoint);
        account.validateUserOp(userOp, MSG_HASH, prefund);
        assertEq(entryPoint.balance - epBalBefore, prefund);
    }

    function testExecute() public {
        address target = makeAddr("target");
        vm.deal(address(account), 1 ether);

        vm.prank(entryPoint);
        account.execute(target, 0.1 ether, "");
        assertEq(target.balance, 0.1 ether);
    }

    function testRotateSigner() public {
        address newSigner = makeAddr("newSigner");
        bytes memory newKey = hex"02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe01";

        vm.prank(entryPoint);
        account.execute(
            address(account),
            0,
            abi.encodeCall(SignetAccount.rotateSigner, (newKey, newSigner))
        );
        assertEq(account.signer(), newSigner);
    }

    function _dummyUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }
}
