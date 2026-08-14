// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "./interfaces/ISignetFactory.sol";
import "./interfaces/ISignetGroup.sol";

/// @title SignetGroup
/// @notice Implementation contract for a Signet threshold signing group.
///         Deployed via BeaconProxy; upgrading the beacon upgrades all groups.
contract SignetGroup is Initializable, ISignetGroup {
    // -------------------------------------------------------------------------
    // State — membership
    // -------------------------------------------------------------------------

    address public factory;
    address public manager;
    uint256 public threshold;
    uint256 public removalDelay;

    mapping(address => NodeStatus) public nodeStatus;

    // Active set — swap-and-pop for O(1) removal
    address[] internal _activeNodes;
    mapping(address => uint256) internal _activeNodeIndex;

    // Pending set — same pattern
    address[] internal _pendingNodes;
    mapping(address => uint256) internal _pendingNodeIndex;

    mapping(address => RemovalRequest) internal _removalRequests;

    // -------------------------------------------------------------------------
    // State — OAuth issuers
    // -------------------------------------------------------------------------

    mapping(bytes32 => OAuthIssuer) internal _issuers;
    bytes32[] internal _issuerHashes;
    mapping(bytes32 => uint256) internal _issuerHashIndex;   // 1-based

    // -------------------------------------------------------------------------
    // State — authorization keys
    // -------------------------------------------------------------------------

    mapping(bytes32 => bytes) internal _authKeys;            // keyHash → pubkey
    bytes32[] internal _authKeyHashes;
    mapping(bytes32 => uint256) internal _authKeyHashIndex;  // 1-based

    // -------------------------------------------------------------------------
    // State — on-chain auth resolver (timelocked)
    // -------------------------------------------------------------------------

    AuthResolver    internal _authResolver;   // 1 slot (uint64+address+bool pack)
    PendingResolver internal _pendingResolver; // 3 slots (nested struct breaks slot)

    // -------------------------------------------------------------------------
    // Upgrade-safe storage gap
    // -------------------------------------------------------------------------
    //
    // Reduced from [50] to [46] when the auth-resolver storage above (4 slots:
    // _authResolver = 1, _pendingResolver = 3) was appended. New storage must be
    // added ABOVE this gap and the gap shrunk by the same number of slots so the
    // total layout footprint stays constant across beacon upgrades.

    uint256[46] private __gap;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyManager() {
        require(msg.sender == manager, "not manager");
        _;
    }

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function initialize(
        address _manager,
        address[] calldata nodeAddrs,
        uint256 _threshold,
        uint256 _removalDelay,
        address _factory,
        InitialIssuer[] calldata _initialIssuers,
        bytes[] calldata _initialAuthKeys
    ) external initializer {
        manager = _manager;
        threshold = _threshold;
        removalDelay = _removalDelay;
        factory = _factory;

        for (uint256 i = 0; i < nodeAddrs.length; i++) {
            address node = nodeAddrs[i];
            ISignetFactory.NodeInfo memory info = ISignetFactory(_factory).getNode(node);
            require(info.registered, "node not registered");
            require(nodeStatus[node] == NodeStatus.None, "duplicate node");

            if (info.isOpen) {
                _addToActive(node);
                emit NodeJoined(node);
            } else {
                _addToPending(node);
                emit NodeInvited(node, _manager);
            }
        }

        for (uint256 i = 0; i < _initialIssuers.length; i++) {
            InitialIssuer calldata ini = _initialIssuers[i];
            bytes32 h = keccak256(abi.encodePacked(ini.issuer));
            string[] memory cids = new string[](ini.clientIds.length);
            for (uint256 j = 0; j < ini.clientIds.length; j++) {
                cids[j] = ini.clientIds[j];
            }
            _addIssuer(h, ini.issuer, cids);
        }

        for (uint256 i = 0; i < _initialAuthKeys.length; i++) {
            bytes32 h = keccak256(_initialAuthKeys[i]);
            _addAuthKey(h, _initialAuthKeys[i]);
        }
    }

    // -------------------------------------------------------------------------
    // Membership management
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function inviteNode(address node) external onlyManager {
        ISignetFactory.NodeInfo memory info = ISignetFactory(factory).getNode(node);
        require(info.registered, "node not registered");
        require(nodeStatus[node] == NodeStatus.None, "already in group");

        if (info.isOpen) {
            _addToActive(node);
            emit NodeJoined(node);
        } else {
            _addToPending(node);
            emit NodeInvited(node, msg.sender);
        }
    }

    /// @inheritdoc ISignetGroup
    function acceptInvite(address node) external {
        require(nodeStatus[node] == NodeStatus.Pending, "not pending");
        require(msg.sender == ISignetFactory(factory).getNodeOperator(node), "not operator");
        _removeFromPending(node);
        _addToActive(node);
        emit NodeJoined(node);
    }

    /// @inheritdoc ISignetGroup
    function declineInvite(address node) external {
        require(nodeStatus[node] == NodeStatus.Pending, "not pending");
        require(msg.sender == ISignetFactory(factory).getNodeOperator(node), "not operator");
        _removeFromPending(node);
        emit NodeDeclined(node);
    }

    /// @inheritdoc ISignetGroup
    function queueRemoval(address node) external {
        require(
            msg.sender == manager || msg.sender == ISignetFactory(factory).getNodeOperator(node),
            "not manager or operator"
        );
        require(nodeStatus[node] == NodeStatus.Active, "node not active");
        require(_removalRequests[node].executeAfter == 0, "removal already queued");

        uint256 executeAfter = block.timestamp + removalDelay;
        _removalRequests[node] = RemovalRequest({
            executeAfter: executeAfter,
            initiator: msg.sender
        });
        emit RemovalQueued(node, msg.sender, executeAfter);
    }

    /// @inheritdoc ISignetGroup
    function cancelRemoval(address node) external {
        RemovalRequest memory req = _removalRequests[node];
        require(req.executeAfter != 0, "no queued removal");
        require(msg.sender == req.initiator, "not initiator");
        delete _removalRequests[node];
        emit RemovalCancelled(node, msg.sender);
    }

    /// @inheritdoc ISignetGroup
    function executeRemoval(address node) external {
        RemovalRequest memory req = _removalRequests[node];
        require(req.executeAfter != 0, "no queued removal");
        require(block.timestamp >= req.executeAfter, "delay not elapsed");

        // Removing this node must not drop the active set below threshold.
        // threshold is immutable after initialization, so a quorum-breaking
        // removal would permanently brick the group (all keys unrecoverable).
        // The active node being removed is still counted in _activeNodes here,
        // so the post-removal size is length - 1; require length - 1 >= threshold
        // (equivalently length > threshold, which also avoids unsigned underflow).
        require(_activeNodes.length > threshold, "removal would break quorum");

        delete _removalRequests[node];
        _removeFromActive(node);
        emit NodeRemoved(node);
    }

    /// @inheritdoc ISignetGroup
    function transferManager(address newManager) external onlyManager {
        address old = manager;
        manager = newManager;
        emit ManagerTransferred(old, newManager);
    }

    // -------------------------------------------------------------------------
    // OAuth issuer management (immediate, manager-only)
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function addIssuer(string calldata issuer, string[] calldata clientIds) external onlyManager {
        bytes32 h = keccak256(abi.encodePacked(issuer));
        require(_issuerHashIndex[h] == 0, "issuer already exists");

        string[] memory cids = new string[](clientIds.length);
        for (uint256 i = 0; i < clientIds.length; i++) {
            cids[i] = clientIds[i];
        }
        _addIssuer(h, issuer, cids);
    }

    /// @inheritdoc ISignetGroup
    function removeIssuer(bytes32 issuerHash) external onlyManager {
        require(_issuerHashIndex[issuerHash] != 0, "issuer not found");

        string memory iss = _issuers[issuerHash].issuer;

        // Swap-and-pop removal from _issuerHashes
        uint256 idx = _issuerHashIndex[issuerHash] - 1; // 0-based
        uint256 last = _issuerHashes.length - 1;
        if (idx != last) {
            bytes32 tail = _issuerHashes[last];
            _issuerHashes[idx] = tail;
            _issuerHashIndex[tail] = idx + 1; // 1-based
        }
        _issuerHashes.pop();
        delete _issuerHashIndex[issuerHash];
        delete _issuers[issuerHash];

        emit IssuerRemoved(issuerHash, iss);
    }

    // -------------------------------------------------------------------------
    // Authorization key management (immediate, manager-only)
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function addAuthKey(bytes calldata pubkey) external onlyManager {
        bytes32 h = keccak256(pubkey);
        require(_authKeyHashIndex[h] == 0, "auth key already exists");
        _addAuthKey(h, pubkey);
    }

    /// @inheritdoc ISignetGroup
    function removeAuthKey(bytes32 keyHash) external onlyManager {
        require(_authKeyHashIndex[keyHash] != 0, "auth key not found");

        bytes memory pubkey = _authKeys[keyHash];

        // Swap-and-pop removal from _authKeyHashes
        uint256 idx = _authKeyHashIndex[keyHash] - 1; // 0-based
        uint256 last = _authKeyHashes.length - 1;
        if (idx != last) {
            bytes32 tail = _authKeyHashes[last];
            _authKeyHashes[idx] = tail;
            _authKeyHashIndex[tail] = idx + 1; // 1-based
        }
        _authKeyHashes.pop();
        delete _authKeyHashIndex[keyHash];
        delete _authKeys[keyHash];

        emit AuthKeyRemoved(keyHash, pubkey);
    }

    // -------------------------------------------------------------------------
    // On-chain auth resolver management (manager-only, timelocked)
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function queueAuthResolver(
        uint64 chainId,
        address resolver,
        bool requireCanonicalSubject
    ) external onlyManager {
        require(_pendingResolver.executeAfter == 0, "resolver change already queued");
        // A non-zero resolver must declare which chain it lives on; a zero
        // resolver (clearing the binding) must not carry stray config.
        if (resolver == address(0)) {
            require(chainId == 0 && !requireCanonicalSubject, "clear must be zeroed");
        } else {
            require(chainId != 0, "chainId required");
        }

        uint256 executeAfter = block.timestamp + removalDelay;
        _pendingResolver = PendingResolver({
            executeAfter: executeAfter,
            next: AuthResolver({
                chainId: chainId,
                resolver: resolver,
                requireCanonicalSubject: requireCanonicalSubject
            }),
            initiator: msg.sender
        });
        emit AuthResolverQueued(chainId, resolver, requireCanonicalSubject, executeAfter);
    }

    /// @inheritdoc ISignetGroup
    function cancelAuthResolver() external {
        PendingResolver memory pending = _pendingResolver;
        require(pending.executeAfter != 0, "no queued resolver change");
        require(msg.sender == pending.initiator, "not initiator");
        delete _pendingResolver;
        emit AuthResolverCancelled(msg.sender);
    }

    /// @inheritdoc ISignetGroup
    function executeAuthResolver() external {
        PendingResolver memory pending = _pendingResolver;
        require(pending.executeAfter != 0, "no queued resolver change");
        require(block.timestamp >= pending.executeAfter, "delay not elapsed");

        _authResolver = pending.next;
        delete _pendingResolver;
        emit AuthResolverSet(
            pending.next.chainId,
            pending.next.resolver,
            pending.next.requireCanonicalSubject
        );
    }

    // -------------------------------------------------------------------------
    // Reshare
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function requestReshare() external onlyManager {
        require(_activeNodes.length >= threshold, "not enough active nodes");
        emit ReshareRequested(msg.sender);
    }

    // -------------------------------------------------------------------------
    // Views — membership
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function getActiveNodes() external view returns (address[] memory) {
        return _activeNodes;
    }

    /// @inheritdoc ISignetGroup
    function getPendingNodes() external view returns (address[] memory) {
        return _pendingNodes;
    }

    /// @inheritdoc ISignetGroup
    function getPendingRemovals() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < _activeNodes.length; i++) {
            if (_removalRequests[_activeNodes[i]].executeAfter > 0) count++;
        }
        address[] memory result = new address[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < _activeNodes.length; i++) {
            if (_removalRequests[_activeNodes[i]].executeAfter > 0) {
                result[j++] = _activeNodes[i];
            }
        }
        return result;
    }

    /// @inheritdoc ISignetGroup
    function quorum() external view returns (uint256) {
        return threshold;
    }

    /// @inheritdoc ISignetGroup
    function isOperational() external view returns (bool) {
        return _activeNodes.length >= threshold;
    }

    /// @inheritdoc ISignetGroup
    function removalRequests(address node) external view returns (RemovalRequest memory) {
        return _removalRequests[node];
    }

    // -------------------------------------------------------------------------
    // Views — OAuth issuers
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function getIssuers() external view returns (OAuthIssuer[] memory) {
        uint256 len = _issuerHashes.length;
        OAuthIssuer[] memory result = new OAuthIssuer[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = _issuers[_issuerHashes[i]];
        }
        return result;
    }

    /// @inheritdoc ISignetGroup
    function isClientIdTrusted(bytes32 issuerHash, string calldata clientId) external view returns (bool) {
        if (_issuerHashIndex[issuerHash] == 0) return false;
        OAuthIssuer storage iss = _issuers[issuerHash];
        bytes32 cidHash = keccak256(bytes(clientId));
        for (uint256 i = 0; i < iss.clientIds.length; i++) {
            if (keccak256(bytes(iss.clientIds[i])) == cidHash) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Views — authorization keys
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function getAuthKeys() external view returns (bytes[] memory) {
        uint256 len = _authKeyHashes.length;
        bytes[] memory result = new bytes[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = _authKeys[_authKeyHashes[i]];
        }
        return result;
    }

    /// @inheritdoc ISignetGroup
    function isAuthKeyTrusted(bytes32 keyHash) external view returns (bool) {
        return _authKeyHashIndex[keyHash] != 0;
    }

    // -------------------------------------------------------------------------
    // Views — on-chain auth resolver
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function getAuthResolver() external view returns (AuthResolver memory) {
        return _authResolver;
    }

    /// @inheritdoc ISignetGroup
    function getPendingAuthResolver() external view returns (PendingResolver memory) {
        return _pendingResolver;
    }

    // -------------------------------------------------------------------------
    // Internal helpers — membership
    // -------------------------------------------------------------------------

    function _addToActive(address node) internal {
        _activeNodeIndex[node] = _activeNodes.length;
        _activeNodes.push(node);
        nodeStatus[node] = NodeStatus.Active;
        ISignetFactory(factory).nodeActivated(node);
    }

    function _removeFromActive(address node) internal {
        uint256 idx = _activeNodeIndex[node];
        uint256 last = _activeNodes.length - 1;
        if (idx != last) {
            address tail = _activeNodes[last];
            _activeNodes[idx] = tail;
            _activeNodeIndex[tail] = idx;
        }
        _activeNodes.pop();
        delete _activeNodeIndex[node];
        delete nodeStatus[node];
        ISignetFactory(factory).nodeDeactivated(node);
    }

    function _addToPending(address node) internal {
        _pendingNodeIndex[node] = _pendingNodes.length;
        _pendingNodes.push(node);
        nodeStatus[node] = NodeStatus.Pending;
    }

    function _removeFromPending(address node) internal {
        uint256 idx = _pendingNodeIndex[node];
        uint256 last = _pendingNodes.length - 1;
        if (idx != last) {
            address tail = _pendingNodes[last];
            _pendingNodes[idx] = tail;
            _pendingNodeIndex[tail] = idx;
        }
        _pendingNodes.pop();
        delete _pendingNodeIndex[node];
        delete nodeStatus[node];
    }

    // -------------------------------------------------------------------------
    // Internal helpers — issuers
    // -------------------------------------------------------------------------

    function _addIssuer(bytes32 h, string memory issuer, string[] memory clientIds) internal {
        _issuerHashes.push(h);
        _issuerHashIndex[h] = _issuerHashes.length; // 1-based
        OAuthIssuer storage stored = _issuers[h];
        stored.issuer = issuer;
        for (uint256 i = 0; i < clientIds.length; i++) {
            // An empty client id is never satisfiable and is not a way to say
            // "no restriction" — nodes gate the allowlist on clientIds.length,
            // so [""] enables the allowlist with a single entry no token can
            // ever match, rejecting every client from an otherwise trusted
            // issuer. Registering [""] instead of [] is what silently broke
            // OAuth auth on testnet group 0xa5B9…8429. Pass an empty array to
            // mean "any client from this issuer".
            require(bytes(clientIds[i]).length > 0, "empty client id");
            stored.clientIds.push(clientIds[i]);
        }
        emit IssuerAdded(h, issuer, clientIds);
    }

    // -------------------------------------------------------------------------
    // Internal helpers — authorization keys
    // -------------------------------------------------------------------------

    function _addAuthKey(bytes32 h, bytes memory pubkey) internal {
        _authKeyHashes.push(h);
        _authKeyHashIndex[h] = _authKeyHashes.length; // 1-based
        _authKeys[h] = pubkey;
        emit AuthKeyAdded(h, pubkey);
    }
}
