// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../contracts/interfaces/ISignetAuthResolver.sol";

/// @dev Test double for ISignetAuthResolver. Lets a test set the (ok, subject)
///      answer per account, plus a global default. When `senderSensitive` is on,
///      `resolve` folds msg.sender into the subject — used to prove the node
///      pins `from = 0x0` on its eth_call (R-2): a correct node always sees the
///      address(0) variant.
contract MockAuthResolver is ISignetAuthResolver {
    struct Answer {
        bool    set;
        bool    ok;
        bytes32 subject;
    }

    mapping(address => Answer) internal _answers;
    bool    public defaultOk;
    bytes32 public defaultSubject;
    bool    public senderSensitive;

    function setAnswer(address account, bool ok, bytes32 subject) external {
        _answers[account] = Answer({set: true, ok: ok, subject: subject});
    }

    function setDefault(bool ok, bytes32 subject) external {
        defaultOk = ok;
        defaultSubject = subject;
    }

    function setSenderSensitive(bool on) external {
        senderSensitive = on;
    }

    /// @inheritdoc ISignetAuthResolver
    function resolve(address account) external view returns (bool ok, bytes32 subject) {
        Answer memory a = _answers[account];
        if (a.set) {
            (ok, subject) = (a.ok, a.subject);
        } else {
            (ok, subject) = (defaultOk, defaultSubject);
        }
        if (senderSensitive) {
            subject = keccak256(abi.encodePacked(subject, msg.sender));
        }
    }

    /// @inheritdoc ISignetAuthResolver
    function typeAndVersion() external pure returns (string memory) {
        return "MockAuthResolver 1.0.0";
    }
}
