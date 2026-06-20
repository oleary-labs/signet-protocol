// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISignetAuthResolver
/// @notice One Signet-defined interface that an on-chain identity authority (or a
///         thin adapter wrapping one) implements so a Signet group can gate
///         session creation on it. See docs/DESIGN-ONCHAIN-AUTH-RESOLVER.md.
///
///         This is the *auth* lane — "who may open a session" — a sibling of the
///         group's trusted OAuth issuers, NOT of key scopes (which constrain what
///         a key may sign).
///
///         Concrete provider adapters (e.g. ACE/CCID, allowlist, ERC-8004,
///         soulbound) live in a separate repo; this repo ships only the interface
///         and a mock for tests.
interface ISignetAuthResolver {
    /// @notice Authorize + resolve an address in a single view call.
    /// @dev MUST be a non-reverting view and a pure function of chain state at a
    ///      block (no per-call randomness, no branching on msg.sender/tx.origin),
    ///      so independent Signet nodes reading at the same pinned block agree.
    ///      Return ok=false on any failure rather than reverting.
    /// @param account The address recovered from the caller's SIWE signature.
    /// @return ok      Whether this address may open a session for the group.
    /// @return subject Canonical principal to namespace the session under.
    ///                 bytes32(0) = authorized but no canonical id (the group's
    ///                 requireCanonicalSubject flag decides whether that is
    ///                 acceptable).
    function resolve(address account) external view returns (bool ok, bytes32 subject);

    /// @notice Type + semantic version string, so nodes can refuse unknown
    ///         resolver versions. Convention follows Chainlink's
    ///         "Name 1.0.0" form.
    function typeAndVersion() external pure returns (string memory);
}
