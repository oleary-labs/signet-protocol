// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import "./interfaces/ISignetFactory.sol";
import "./interfaces/ISignetGroup.sol";

/// @title SignetFactory
/// @notice UUPS-upgradeable factory that maintains a global node registry and
///         deploys SignetGroup instances via an UpgradeableBeacon.
contract SignetFactory is Initializable, OwnableUpgradeable, UUPSUpgradeable, ISignetFactory {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    uint256 public constant MIN_REMOVAL_DELAY = 1 days;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    mapping(address => NodeInfo) public nodes;
    address[] public registeredNodes;

    address public groupBeacon;
    address[] public groups;
    mapping(address => bool) public isGroup;

    // Reverse mapping: node address → list of groups where the node is active
    mapping(address => address[]) internal _nodeGroups;
    // 1-based index for O(1) swap-and-pop: _nodeGroupIndex[node][group] = position in _nodeGroups[node]
    mapping(address => mapping(address => uint256)) internal _nodeGroupIndex;

    // -------------------------------------------------------------------------
    // Upgrade-safe storage gap
    // -------------------------------------------------------------------------

    uint256[48] private __gap;

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    /// @notice One-time initializer (replaces constructor for upgradeable contracts).
    /// @param admin        Address that will own the factory (and thus the beacon).
    /// @param groupImpl    Initial SignetGroup implementation address.
    function initialize(address admin, address groupImpl) external initializer {
        __Ownable_init(admin);
        groupBeacon = address(new UpgradeableBeacon(groupImpl, address(this)));
    }

    // -------------------------------------------------------------------------
    // Node registry
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetFactory
    function registerNode(bytes calldata pubkey, bool isOpen, address operator) external {
        require(!nodes[msg.sender].registered, "already registered");
        require(_pubkeyToAddress(pubkey) == msg.sender, "pubkey does not match sender");

        nodes[msg.sender] = NodeInfo({
            pubkey: pubkey,
            isOpen: isOpen,
            registered: true,
            registeredAt: block.timestamp,
            operator: operator
        });
        registeredNodes.push(msg.sender);

        emit NodeRegistered(msg.sender, pubkey, isOpen, operator);
    }

    /// @inheritdoc ISignetFactory
    function updateOpenStatus(address node, bool isOpen) external {
        require(nodes[node].registered, "not registered");
        require(msg.sender == _effectiveOperator(node), "not operator");
        nodes[node].isOpen = isOpen;
        emit NodeOpenStatusChanged(node, isOpen);
    }

    /// @inheritdoc ISignetFactory
    function getNode(address node) external view returns (NodeInfo memory) {
        return nodes[node];
    }

    /// @inheritdoc ISignetFactory
    function setOperator(address node, address newOperator) external {
        require(nodes[node].registered, "not registered");
        require(msg.sender == _effectiveOperator(node), "not operator");
        nodes[node].operator = newOperator;
        emit OperatorChanged(node, newOperator);
    }

    /// @inheritdoc ISignetFactory
    function getRegisteredNodes() external view returns (address[] memory) {
        return registeredNodes;
    }

    /// @inheritdoc ISignetFactory
    function getNodeOperator(address node) external view returns (address) {
        return _effectiveOperator(node);
    }

    // -------------------------------------------------------------------------
    // Group factory
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetFactory
    function createGroup(
        address[] calldata nodeAddrs,
        uint256 threshold,
        uint256 removalDelay,
        uint256 issuerAddDelay,
        uint256 issuerRemovalDelay,
        ISignetGroup.InitialIssuer[] calldata initialIssuers,
        uint256 authKeyAddDelay,
        uint256 authKeyRemovalDelay,
        bytes[] calldata initialAuthKeys
    ) external returns (address group) {
        require(removalDelay >= MIN_REMOVAL_DELAY, "removal delay too short");
        require(nodeAddrs.length > threshold, "threshold too high for node count");

        // Two-step deploy: set isGroup BEFORE calling initialize so that
        // nodeActivated callbacks (triggered inside _addToActive during initialize)
        // pass the require(isGroup[msg.sender]) check.
        group = address(new BeaconProxy(groupBeacon, ""));
        groups.push(group);
        isGroup[group] = true;

        ISignetGroup(group).initialize(
            msg.sender,
            nodeAddrs,
            threshold,
            removalDelay,
            address(this),
            issuerAddDelay,
            issuerRemovalDelay,
            initialIssuers,
            authKeyAddDelay,
            authKeyRemovalDelay,
            initialAuthKeys
        );

        emit GroupCreated(group, msg.sender, threshold);
    }

    /// @inheritdoc ISignetFactory
    function upgradeGroupImplementation(address newImpl) external onlyOwner {
        UpgradeableBeacon(groupBeacon).upgradeTo(newImpl);
    }

    /// @inheritdoc ISignetFactory
    function getGroups() external view returns (address[] memory) {
        return groups;
    }

    // -------------------------------------------------------------------------
    // Group membership callbacks
    // -------------------------------------------------------------------------

    /// @inheritdoc ISignetFactory
    function nodeActivated(address node) external {
        require(isGroup[msg.sender], "not a group");
        address group = msg.sender;
        if (_nodeGroupIndex[node][group] == 0) {
            _nodeGroups[node].push(group);
            _nodeGroupIndex[node][group] = _nodeGroups[node].length; // 1-based
            emit NodeActivatedInGroup(node, group);
        }
    }

    /// @inheritdoc ISignetFactory
    function nodeDeactivated(address node) external {
        require(isGroup[msg.sender], "not a group");
        address group = msg.sender;
        uint256 idx = _nodeGroupIndex[node][group];
        if (idx == 0) return; // not tracked
        uint256 arrIdx = idx - 1;
        uint256 last = _nodeGroups[node].length - 1;
        if (arrIdx != last) {
            address tail = _nodeGroups[node][last];
            _nodeGroups[node][arrIdx] = tail;
            _nodeGroupIndex[node][tail] = idx; // keep 1-based
        }
        _nodeGroups[node].pop();
        delete _nodeGroupIndex[node][group];
        emit NodeDeactivatedInGroup(node, group);
    }

    /// @inheritdoc ISignetFactory
    function getNodeGroups(address node) external view returns (address[] memory) {
        return _nodeGroups[node];
    }

    /// @inheritdoc ISignetFactory
    function getNodePubkey(address node) external view returns (bytes memory) {
        return nodes[node].pubkey;
    }

    // -------------------------------------------------------------------------
    // UUPS hook
    // -------------------------------------------------------------------------

    /// @dev Only the owner may upgrade the factory itself.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @dev Returns the effective operator for a node: stored operator, or node itself if zero.
    function _effectiveOperator(address node) internal view returns (address) {
        address op = nodes[node].operator;
        return op == address(0) ? node : op;
    }

    /// @dev Derives the Ethereum address from an uncompressed secp256k1 public key.
    ///      pubkey must be 65 bytes with a 0x04 prefix.
    function _pubkeyToAddress(bytes calldata pubkey) internal pure returns (address) {
        require(pubkey.length == 65 && pubkey[0] == 0x04, "invalid uncompressed pubkey");
        return address(uint160(uint256(keccak256(pubkey[1:65]))));
    }
}
