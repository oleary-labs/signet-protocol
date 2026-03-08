// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ISignetGroup.sol";

/// @title ISignetFactory
/// @notice Interface for the Signet node registry and group factory.
interface ISignetFactory {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    struct NodeInfo {
        bytes pubkey;       // 65-byte uncompressed secp256k1 pubkey (0x04 || x || y)
        bool isOpen;        // true = any group may add this node without acceptance
        bool registered;
        uint256 registeredAt;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event NodeRegistered(address indexed node, bytes pubkey, bool isOpen);
    event NodeOpenStatusChanged(address indexed node, bool isOpen);
    event GroupCreated(address indexed group, address indexed creator, uint256 threshold);
    event NodeActivatedInGroup(address indexed node, address indexed group);
    event NodeDeactivatedInGroup(address indexed node, address indexed group);

    // -------------------------------------------------------------------------
    // Node registry
    // -------------------------------------------------------------------------

    /// @notice Register the caller as a signet node.
    /// @param pubkey 65-byte uncompressed secp256k1 public key (0x04 prefix).
    /// @param isOpen Whether this node accepts group invitations automatically.
    function registerNode(bytes calldata pubkey, bool isOpen) external;

    /// @notice Toggle the open/permissioned flag for the caller's node.
    function updateOpenStatus(bool isOpen) external;

    /// @notice Return NodeInfo for a given address.
    function getNode(address node) external view returns (NodeInfo memory);

    /// @notice Return the full list of ever-registered node addresses.
    function getRegisteredNodes() external view returns (address[] memory);

    // -------------------------------------------------------------------------
    // Group factory
    // -------------------------------------------------------------------------

    /// @notice Deploy a new SignetGroup via the beacon proxy.
    /// @param nodeAddrs          Initial set of node addresses.
    /// @param threshold          Maximum tolerated corruptions (quorum = threshold + 1).
    /// @param removalDelay       Seconds delay before a queued node removal can execute.
    /// @param issuerAddDelay     Seconds delay before a queued issuer addition can execute.
    /// @param issuerRemovalDelay Seconds delay before a queued issuer removal can execute.
    /// @param initialIssuers     OAuth issuers added immediately at creation (no delay).
    function createGroup(
        address[] calldata nodeAddrs,
        uint256 threshold,
        uint256 removalDelay,
        uint256 issuerAddDelay,
        uint256 issuerRemovalDelay,
        ISignetGroup.InitialIssuer[] calldata initialIssuers
    ) external returns (address group);

    /// @notice Upgrade the SignetGroup implementation for all groups.
    function upgradeGroupImplementation(address newImpl) external;

    /// @notice Return the full list of deployed group addresses.
    function getGroups() external view returns (address[] memory);

    /// @notice Address of the UpgradeableBeacon that all groups point to.
    function groupBeacon() external view returns (address);

    /// @notice Whether an address is a group deployed by this factory.
    function isGroup(address) external view returns (bool);

    /// @notice Minimum removal delay enforced on group creation.
    function MIN_REMOVAL_DELAY() external view returns (uint256);

    // -------------------------------------------------------------------------
    // Group membership callbacks (called by groups, not directly by users)
    // -------------------------------------------------------------------------

    /// @notice Called by a group when a node becomes active. Only callable by known groups.
    function nodeActivated(address node) external;

    /// @notice Called by a group when a node leaves the active set. Only callable by known groups.
    function nodeDeactivated(address node) external;

    /// @notice Return all group addresses where node is currently active.
    function getNodeGroups(address node) external view returns (address[] memory);

    /// @notice Return the stored public key for a registered node.
    function getNodePubkey(address node) external view returns (bytes memory);
}
