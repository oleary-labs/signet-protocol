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

    uint256 public issuerAddDelay;
    uint256 public issuerRemovalDelay;

    mapping(bytes32 => OAuthIssuer) internal _issuers;
    bytes32[] internal _issuerHashes;
    mapping(bytes32 => uint256) internal _issuerHashIndex;   // 1-based

    mapping(bytes32 => PendingIssuerAddition) internal _pendingAdditions;
    mapping(bytes32 => uint256) internal _pendingRemovals;   // executeAfter timestamp

    // -------------------------------------------------------------------------
    // Upgrade-safe storage gap  (50 original − 7 new vars = 43)
    // -------------------------------------------------------------------------

    uint256[43] private __gap;

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
        uint256 _issuerAddDelay,
        uint256 _issuerRemovalDelay,
        InitialIssuer[] calldata _initialIssuers
    ) external initializer {
        manager = _manager;
        threshold = _threshold;
        removalDelay = _removalDelay;
        factory = _factory;
        issuerAddDelay = _issuerAddDelay;
        issuerRemovalDelay = _issuerRemovalDelay;

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

        // Seed initial issuers immediately — no delay applied.
        for (uint256 i = 0; i < _initialIssuers.length; i++) {
            InitialIssuer calldata ini = _initialIssuers[i];
            bytes32 h = keccak256(abi.encodePacked(ini.issuer));
            // Copy calldata string[] to memory for _addIssuer
            string[] memory cids = new string[](ini.clientIds.length);
            for (uint256 j = 0; j < ini.clientIds.length; j++) {
                cids[j] = ini.clientIds[j];
            }
            _addIssuer(h, ini.issuer, cids);
        }
    }

    // -------------------------------------------------------------------------
    // Membership management
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function inviteNode(address node) external {
        require(msg.sender == manager, "not manager");
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
    function acceptInvite() external {
        require(nodeStatus[msg.sender] == NodeStatus.Pending, "not pending");
        _removeFromPending(msg.sender);
        _addToActive(msg.sender);
        emit NodeJoined(msg.sender);
    }

    /// @inheritdoc ISignetGroup
    function declineInvite() external {
        require(nodeStatus[msg.sender] == NodeStatus.Pending, "not pending");
        _removeFromPending(msg.sender);
        emit NodeDeclined(msg.sender);
    }

    /// @inheritdoc ISignetGroup
    function queueRemoval(address node) external {
        require(
            msg.sender == manager || msg.sender == node,
            "not manager or self"
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
        require(
            msg.sender == manager || msg.sender == req.initiator,
            "not manager or initiator"
        );
        delete _removalRequests[node];
        emit RemovalCancelled(node, msg.sender);
    }

    /// @inheritdoc ISignetGroup
    function executeRemoval(address node) external {
        RemovalRequest memory req = _removalRequests[node];
        require(req.executeAfter != 0, "no queued removal");
        require(block.timestamp >= req.executeAfter, "delay not elapsed");

        delete _removalRequests[node];
        _removeFromActive(node);
        emit NodeRemoved(node);
    }

    /// @inheritdoc ISignetGroup
    function transferManager(address newManager) external {
        require(msg.sender == manager, "not manager");
        address old = manager;
        manager = newManager;
        emit ManagerTransferred(old, newManager);
    }

    // -------------------------------------------------------------------------
    // OAuth issuer management
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetGroup
    function queueAddIssuer(string calldata issuer, string[] calldata clientIds) external {
        require(msg.sender == manager, "not manager");
        bytes32 h = keccak256(abi.encodePacked(issuer));
        require(_issuerHashIndex[h] == 0, "issuer already exists");
        require(_pendingAdditions[h].executeAfter == 0, "addition already queued");

        uint256 executeAfter = block.timestamp + issuerAddDelay;

        // Copy calldata arrays to storage via PendingIssuerAddition
        PendingIssuerAddition storage p = _pendingAdditions[h];
        p.issuer = issuer;
        p.executeAfter = executeAfter;
        for (uint256 i = 0; i < clientIds.length; i++) {
            p.clientIds.push(clientIds[i]);
        }

        emit IssuerAddQueued(h, issuer, clientIds, executeAfter);
    }

    /// @inheritdoc ISignetGroup
    function cancelAddIssuer(bytes32 issuerHash) external {
        require(msg.sender == manager, "not manager");
        require(_pendingAdditions[issuerHash].executeAfter != 0, "not pending");
        delete _pendingAdditions[issuerHash];
        emit IssuerAddCancelled(issuerHash);
    }

    /// @inheritdoc ISignetGroup
    function executeAddIssuer(bytes32 issuerHash) external {
        PendingIssuerAddition storage p = _pendingAdditions[issuerHash];
        require(p.executeAfter != 0, "not pending");
        require(block.timestamp >= p.executeAfter, "delay not elapsed");
        require(_issuerHashIndex[issuerHash] == 0, "issuer already exists");

        string memory iss = p.issuer;
        string[] memory cids = new string[](p.clientIds.length);
        for (uint256 i = 0; i < p.clientIds.length; i++) {
            cids[i] = p.clientIds[i];
        }
        delete _pendingAdditions[issuerHash];
        _addIssuer(issuerHash, iss, cids);
    }

    /// @inheritdoc ISignetGroup
    function queueRemoveIssuer(bytes32 issuerHash) external {
        require(msg.sender == manager, "not manager");
        require(_issuerHashIndex[issuerHash] != 0, "issuer not found");
        require(_pendingRemovals[issuerHash] == 0, "removal already queued");

        uint256 executeAfter = block.timestamp + issuerRemovalDelay;
        _pendingRemovals[issuerHash] = executeAfter;
        emit IssuerRemovalQueued(issuerHash, executeAfter);
    }

    /// @inheritdoc ISignetGroup
    function cancelRemoveIssuer(bytes32 issuerHash) external {
        require(msg.sender == manager, "not manager");
        require(_pendingRemovals[issuerHash] != 0, "no queued removal");
        delete _pendingRemovals[issuerHash];
        emit IssuerRemovalCancelled(issuerHash);
    }

    /// @inheritdoc ISignetGroup
    function executeRemoveIssuer(bytes32 issuerHash) external {
        uint256 executeAfter = _pendingRemovals[issuerHash];
        require(executeAfter != 0, "no queued removal");
        require(block.timestamp >= executeAfter, "delay not elapsed");

        string memory iss = _issuers[issuerHash].issuer;
        delete _pendingRemovals[issuerHash];

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
        return threshold + 1;
    }

    /// @inheritdoc ISignetGroup
    function isOperational() external view returns (bool) {
        return _activeNodes.length >= threshold + 1;
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
            stored.clientIds.push(clientIds[i]);
        }
        emit IssuerAdded(h, issuer, clientIds);
    }
}
