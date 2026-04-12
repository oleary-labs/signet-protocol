// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISignetGroup
/// @notice Interface for a Signet threshold signing group deployed via BeaconProxy.
interface ISignetGroup {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    enum NodeStatus { None, Pending, Active }

    struct RemovalRequest {
        uint256 executeAfter;
        address initiator;
    }

    struct OAuthIssuer {
        string   issuer;      // iss URL (OpenID discovery base)
        string[] clientIds;   // allowed azp/client_id values
    }

    struct PendingIssuerAddition {
        string   issuer;
        string[] clientIds;
        uint256  executeAfter;
    }

    /// @notice Used only in createGroup/initialize calldata to seed issuers without a delay.
    struct InitialIssuer {
        string   issuer;
        string[] clientIds;
    }

    struct PendingAuthKeyAddition {
        bytes   pubkey;
        uint256 executeAfter;
    }

    // -------------------------------------------------------------------------
    // Events — node membership
    // -------------------------------------------------------------------------

    event NodeInvited(address indexed node, address indexed invitedBy);
    event NodeJoined(address indexed node);
    event NodeDeclined(address indexed node);
    event RemovalQueued(address indexed node, address indexed initiator, uint256 executeAfter);
    event RemovalCancelled(address indexed node, address indexed cancelledBy);
    event NodeRemoved(address indexed node);
    event ManagerTransferred(address indexed oldManager, address indexed newManager);

    // -------------------------------------------------------------------------
    // Events — OAuth issuer management
    // -------------------------------------------------------------------------

    event IssuerAddQueued    (bytes32 indexed h, string issuer, string[] clientIds, uint256 executeAfter);
    event IssuerAddCancelled (bytes32 indexed h);
    event IssuerAdded        (bytes32 indexed h, string issuer, string[] clientIds);
    event IssuerRemovalQueued(bytes32 indexed h, uint256 executeAfter);
    event IssuerRemovalCancelled(bytes32 indexed h);
    event IssuerRemoved      (bytes32 indexed h, string issuer);

    // -------------------------------------------------------------------------
    // Events — authorization key management
    // -------------------------------------------------------------------------

    event AuthKeyAddQueued      (bytes32 indexed keyHash, bytes pubkey, uint256 executeAfter);
    event AuthKeyAddCancelled   (bytes32 indexed keyHash);
    event AuthKeyAdded          (bytes32 indexed keyHash, bytes pubkey);
    event AuthKeyRemovalQueued  (bytes32 indexed keyHash, uint256 executeAfter);
    event AuthKeyRemovalCancelled(bytes32 indexed keyHash);
    event AuthKeyRemoved        (bytes32 indexed keyHash, bytes pubkey);

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    /// @notice Initialize the group (called once through the BeaconProxy constructor data).
    function initialize(
        address _manager,
        address[] calldata nodeAddrs,
        uint256 _threshold,
        uint256 _removalDelay,
        address _factory,
        uint256 _issuerAddDelay,
        uint256 _issuerRemovalDelay,
        InitialIssuer[] calldata _initialIssuers,
        uint256 _authKeyAddDelay,
        uint256 _authKeyRemovalDelay,
        bytes[] calldata _initialAuthKeys
    ) external;

    // -------------------------------------------------------------------------
    // Membership management
    // -------------------------------------------------------------------------

    /// @notice Invite a registered node post-creation.
    function inviteNode(address node) external;

    /// @notice Accept an existing pending invitation.
    ///         Caller must be the node's effective operator (node itself if no operator set).
    function acceptInvite(address node) external;

    /// @notice Decline a pending invitation.
    ///         Caller must be the node's effective operator (node itself if no operator set).
    function declineInvite(address node) external;

    /// @notice Queue a removal for an active node (manager or node itself).
    function queueRemoval(address node) external;

    /// @notice Cancel a queued removal (manager or original initiator).
    function cancelRemoval(address node) external;

    /// @notice Execute a removal after its delay has elapsed (permissionless).
    function executeRemoval(address node) external;

    /// @notice Transfer the manager role to another address.
    function transferManager(address newManager) external;

    // -------------------------------------------------------------------------
    // OAuth issuer management (manager-only queue/cancel; permissionless execute)
    // -------------------------------------------------------------------------

    /// @notice Queue an issuer addition. Key = keccak256(abi.encodePacked(issuer)).
    function queueAddIssuer(string calldata issuer, string[] calldata clientIds) external;

    /// @notice Cancel a queued issuer addition (manager only).
    function cancelAddIssuer(bytes32 issuerHash) external;

    /// @notice Execute a queued addition after issuerAddDelay has elapsed (permissionless).
    function executeAddIssuer(bytes32 issuerHash) external;

    /// @notice Queue an issuer removal (manager only).
    function queueRemoveIssuer(bytes32 issuerHash) external;

    /// @notice Cancel a queued issuer removal (manager only).
    function cancelRemoveIssuer(bytes32 issuerHash) external;

    /// @notice Execute a queued removal after issuerRemovalDelay has elapsed (permissionless).
    function executeRemoveIssuer(bytes32 issuerHash) external;

    // -------------------------------------------------------------------------
    // Authorization key management (manager-only queue/cancel; permissionless execute)
    // -------------------------------------------------------------------------

    /// @notice Queue an authorization key addition. Key hash = keccak256(pubkey).
    function queueAddAuthKey(bytes calldata pubkey) external;

    /// @notice Cancel a queued authorization key addition (manager only).
    function cancelAddAuthKey(bytes32 keyHash) external;

    /// @notice Execute a queued addition after authKeyAddDelay has elapsed (permissionless).
    function executeAddAuthKey(bytes32 keyHash) external;

    /// @notice Queue an authorization key removal (manager only).
    function queueRemoveAuthKey(bytes32 keyHash) external;

    /// @notice Cancel a queued authorization key removal (manager only).
    function cancelRemoveAuthKey(bytes32 keyHash) external;

    /// @notice Execute a queued removal after authKeyRemovalDelay has elapsed (permissionless).
    function executeRemoveAuthKey(bytes32 keyHash) external;

    // -------------------------------------------------------------------------
    // Views — membership
    // -------------------------------------------------------------------------

    function factory() external view returns (address);
    function manager() external view returns (address);
    function threshold() external view returns (uint256);
    function removalDelay() external view returns (uint256);
    function nodeStatus(address node) external view returns (NodeStatus);
    function removalRequests(address node) external view returns (RemovalRequest memory);
    function getActiveNodes() external view returns (address[] memory);
    function getPendingNodes() external view returns (address[] memory);
    function getPendingRemovals() external view returns (address[] memory);

    /// @notice Returns threshold + 1.
    function quorum() external view returns (uint256);

    /// @notice True when active node count >= quorum().
    function isOperational() external view returns (bool);

    // -------------------------------------------------------------------------
    // Views — OAuth issuers
    // -------------------------------------------------------------------------

    function issuerAddDelay() external view returns (uint256);
    function issuerRemovalDelay() external view returns (uint256);

    /// @notice Returns all currently trusted OAuth issuers for this group.
    function getIssuers() external view returns (OAuthIssuer[] memory);

    /// @notice True when clientId is in the trusted list for the given issuer.
    function isClientIdTrusted(bytes32 issuerHash, string calldata clientId) external view returns (bool);

    // -------------------------------------------------------------------------
    // Views — authorization keys
    // -------------------------------------------------------------------------

    function authKeyAddDelay() external view returns (uint256);
    function authKeyRemovalDelay() external view returns (uint256);

    /// @notice Returns all currently trusted authorization key pubkeys for this group.
    function getAuthKeys() external view returns (bytes[] memory);

    /// @notice True when the given key hash corresponds to a trusted authorization key.
    function isAuthKeyTrusted(bytes32 keyHash) external view returns (bool);
}
