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

    /// @notice Used in createGroup/initialize calldata to seed issuers at creation.
    struct InitialIssuer {
        string   issuer;
        string[] clientIds;
    }

    /// @notice On-chain auth resolver binding (the auth lane — "who may open a
    ///         session"). chainId may differ from the group's home chain.
    ///         resolver == address(0) means no resolver is configured.
    struct AuthResolver {
        uint64  chainId;                 // chain the resolver lives on
        address resolver;                // ISignetAuthResolver implementation
        bool    requireCanonicalSubject; // reject resolve() results with subject == 0
    }

    /// @notice A queued (timelocked) change to the auth resolver binding.
    ///         executeAfter == 0 is the sentinel for "no pending change".
    struct PendingResolver {
        uint256      executeAfter;
        AuthResolver next;
        address      initiator;
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

    event IssuerAdded   (bytes32 indexed h, string issuer, string[] clientIds);
    event IssuerRemoved (bytes32 indexed h, string issuer);

    // -------------------------------------------------------------------------
    // Events — authorization key management
    // -------------------------------------------------------------------------

    event AuthKeyAdded   (bytes32 indexed keyHash, bytes pubkey);
    event AuthKeyRemoved (bytes32 indexed keyHash, bytes pubkey);

    // -------------------------------------------------------------------------
    // Events — on-chain auth resolver (timelocked)
    // -------------------------------------------------------------------------

    event AuthResolverQueued    (uint64 chainId, address indexed resolver, bool requireCanonicalSubject, uint256 executeAfter);
    event AuthResolverCancelled (address indexed initiator);
    event AuthResolverSet       (uint64 chainId, address indexed resolver, bool requireCanonicalSubject);

    // -------------------------------------------------------------------------
    // Events — reshare
    // -------------------------------------------------------------------------

    /// @notice Emitted when a manual key refresh (reshare) is requested.
    ///         Nodes watch for this event and trigger a reshare with the current
    ///         active membership (same committee, refreshed key shares).
    event ReshareRequested(address indexed requestedBy);

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
        InitialIssuer[] calldata _initialIssuers,
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

    /// @notice Cancel a queued removal (only the original initiator).
    function cancelRemoval(address node) external;

    /// @notice Execute a removal after its delay has elapsed (permissionless).
    function executeRemoval(address node) external;

    /// @notice Transfer the manager role to another address.
    function transferManager(address newManager) external;

    // -------------------------------------------------------------------------
    // OAuth issuer management (manager-only, immediate)
    // -------------------------------------------------------------------------

    /// @notice Add an OAuth issuer. Key = keccak256(abi.encodePacked(issuer)).
    function addIssuer(string calldata issuer, string[] calldata clientIds) external;

    /// @notice Remove an OAuth issuer (manager only).
    function removeIssuer(bytes32 issuerHash) external;

    // -------------------------------------------------------------------------
    // Authorization key management (manager-only, immediate)
    // -------------------------------------------------------------------------

    /// @notice Add an authorization key. Key hash = keccak256(pubkey).
    function addAuthKey(bytes calldata pubkey) external;

    /// @notice Remove an authorization key (manager only).
    function removeAuthKey(bytes32 keyHash) external;

    // -------------------------------------------------------------------------
    // On-chain auth resolver management (manager-only, timelocked)
    // -------------------------------------------------------------------------

    /// @notice Queue a change to the group's auth resolver binding. The change
    ///         takes effect only after `removalDelay` elapses and someone calls
    ///         `executeAuthResolver`. The timelock is mandatory: a resolver can
    ///         authorize addresses unilaterally, so its blast radius exceeds an
    ///         issuer's. Pass resolver == address(0) to queue clearing it.
    function queueAuthResolver(uint64 chainId, address resolver, bool requireCanonicalSubject) external;

    /// @notice Cancel a queued auth-resolver change (only the original initiator).
    function cancelAuthResolver() external;

    /// @notice Apply a queued auth-resolver change after its delay has elapsed
    ///         (permissionless, mirroring executeRemoval).
    function executeAuthResolver() external;

    // -------------------------------------------------------------------------
    // Reshare (manager-only)
    // -------------------------------------------------------------------------

    /// @notice Request a manual key refresh (reshare) with the current committee.
    ///         Emits ReshareRequested. Nodes detect the event and coordinate the
    ///         reshare protocol using leader election.
    function requestReshare() external;

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

    /// @notice Returns threshold (minimum honest signers required).
    function quorum() external view returns (uint256);

    /// @notice True when active node count >= threshold.
    function isOperational() external view returns (bool);

    // -------------------------------------------------------------------------
    // Views — OAuth issuers
    // -------------------------------------------------------------------------

    /// @notice Returns all currently trusted OAuth issuers for this group.
    function getIssuers() external view returns (OAuthIssuer[] memory);

    /// @notice True when clientId is in the trusted list for the given issuer.
    function isClientIdTrusted(bytes32 issuerHash, string calldata clientId) external view returns (bool);

    // -------------------------------------------------------------------------
    // Views — authorization keys
    // -------------------------------------------------------------------------

    /// @notice Returns all currently trusted authorization key pubkeys for this group.
    function getAuthKeys() external view returns (bytes[] memory);

    /// @notice True when the given key hash corresponds to a trusted authorization key.
    function isAuthKeyTrusted(bytes32 keyHash) external view returns (bool);

    // -------------------------------------------------------------------------
    // Views — on-chain auth resolver
    // -------------------------------------------------------------------------

    /// @notice Returns the active auth resolver binding (resolver == address(0)
    ///         when none is configured).
    function getAuthResolver() external view returns (AuthResolver memory);

    /// @notice Returns the currently queued auth-resolver change (executeAfter
    ///         == 0 when none is pending).
    function getPendingAuthResolver() external view returns (PendingResolver memory);
}
