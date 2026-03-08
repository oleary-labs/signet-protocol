// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../contracts/SignetFactory.sol";
import "../contracts/SignetGroup.sol";
import "../contracts/interfaces/ISignetFactory.sol";
import "../contracts/interfaces/ISignetGroup.sol";

/// @dev Shared helpers for building valid uncompressed pubkeys from Foundry wallets.
abstract contract PubkeyHelpers is Test {
    /// @dev Returns the 65-byte uncompressed secp256k1 public key for a private key.
    ///      Uses vm.createWallet to obtain the secp256k1 (x, y) coordinates.
    function _uncompressedPubkey(uint256 privKey) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(privKey);
        return abi.encodePacked(bytes1(0x04), bytes32(w.publicKeyX), bytes32(w.publicKeyY));
    }
}

contract SignetFactoryTest is PubkeyHelpers {
    SignetFactory factoryImpl;
    SignetFactory factory;  // proxy
    SignetGroup   groupImpl;

    // Three test nodes with deterministic private keys.
    uint256 constant PK1 = 0xA11CE;
    uint256 constant PK2 = 0xB0B;
    uint256 constant PK3 = 0xCAFE;

    address node1;
    address node2;
    address node3;

    bytes pubkey1;
    bytes pubkey2;
    bytes pubkey3;

    address admin = address(0xAD);

    function setUp() public {
        node1 = vm.addr(PK1);
        node2 = vm.addr(PK2);
        node3 = vm.addr(PK3);

        pubkey1 = _uncompressedPubkey(PK1);
        pubkey2 = _uncompressedPubkey(PK2);
        pubkey3 = _uncompressedPubkey(PK3);

        // Deploy factory implementation + ERC1967 proxy
        groupImpl    = new SignetGroup();
        factoryImpl  = new SignetFactory();
        bytes memory initData = abi.encodeCall(
            SignetFactory.initialize,
            (admin, address(groupImpl))
        );
        factory = SignetFactory(address(new ERC1967Proxy(address(factoryImpl), initData)));
    }

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    function testRegisterNode() public {
        vm.prank(node1);
        vm.expectEmit(true, false, false, true);
        emit ISignetFactory.NodeRegistered(node1, pubkey1, true);
        factory.registerNode(pubkey1, true);

        ISignetFactory.NodeInfo memory info = factory.getNode(node1);
        assertEq(info.registered, true);
        assertEq(info.isOpen, true);
        assertEq(keccak256(info.pubkey), keccak256(pubkey1));
        assertEq(info.registeredAt, block.timestamp);

        address[] memory all = factory.getRegisteredNodes();
        assertEq(all.length, 1);
        assertEq(all[0], node1);
    }

    function testRegisterNode_InvalidLength() public {
        bytes memory bad = new bytes(64);  // missing 0x04 prefix byte
        vm.prank(node1);
        vm.expectRevert("invalid uncompressed pubkey");
        factory.registerNode(bad, false);
    }

    function testRegisterNode_BadPrefix() public {
        bytes memory bad = pubkey1;
        bad[0] = 0x02;  // compressed prefix
        vm.prank(node1);
        vm.expectRevert("invalid uncompressed pubkey");
        factory.registerNode(bad, false);
    }

    function testRegisterNode_WrongAddress() public {
        // node2 tries to register node1's pubkey
        vm.prank(node2);
        vm.expectRevert("pubkey does not match sender");
        factory.registerNode(pubkey1, false);
    }

    function testRegisterNode_AlreadyRegistered() public {
        vm.prank(node1);
        factory.registerNode(pubkey1, true);
        vm.prank(node1);
        vm.expectRevert("already registered");
        factory.registerNode(pubkey1, false);
    }

    // -------------------------------------------------------------------------
    // updateOpenStatus
    // -------------------------------------------------------------------------

    function testUpdateOpenStatus() public {
        vm.prank(node1);
        factory.registerNode(pubkey1, true);

        vm.prank(node1);
        vm.expectEmit(true, false, false, true);
        emit ISignetFactory.NodeOpenStatusChanged(node1, false);
        factory.updateOpenStatus(false);

        assertEq(factory.getNode(node1).isOpen, false);

        vm.prank(node1);
        factory.updateOpenStatus(true);
        assertEq(factory.getNode(node1).isOpen, true);
    }

    function testUpdateOpenStatus_NotRegistered() public {
        vm.prank(node1);
        vm.expectRevert("not registered");
        factory.updateOpenStatus(false);
    }

    // -------------------------------------------------------------------------
    // createGroup — all-open nodes
    // -------------------------------------------------------------------------

    function _registerAll() internal {
        vm.prank(node1); factory.registerNode(pubkey1, true);
        vm.prank(node2); factory.registerNode(pubkey2, true);
        vm.prank(node3); factory.registerNode(pubkey3, true);
    }

    ISignetGroup.InitialIssuer[] internal _noIssuers;

    function testCreateGroup_AllOpen() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        vm.expectEmit(false, true, false, true);
        emit ISignetFactory.GroupCreated(address(0), address(this), 1);
        address group = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);

        assertTrue(factory.isGroup(group));
        assertEq(factory.getGroups().length, 1);
        assertEq(factory.getGroups()[0], group);

        // All nodes should be Active
        ISignetGroup g = ISignetGroup(group);
        assertEq(g.getActiveNodes().length, 3);
        assertEq(g.getPendingNodes().length, 0);
        assertEq(uint8(g.nodeStatus(node1)), uint8(ISignetGroup.NodeStatus.Active));
    }

    // -------------------------------------------------------------------------
    // createGroup — mixed openness
    // -------------------------------------------------------------------------

    function testCreateGroup_MixedOpenness() public {
        vm.prank(node1); factory.registerNode(pubkey1, true);   // open
        vm.prank(node2); factory.registerNode(pubkey2, false);  // not open
        vm.prank(node3); factory.registerNode(pubkey3, true);   // open

        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        address group = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);
        ISignetGroup g = ISignetGroup(group);

        assertEq(g.getActiveNodes().length, 2);   // node1 + node3
        assertEq(g.getPendingNodes().length, 1);  // node2
        assertEq(uint8(g.nodeStatus(node2)), uint8(ISignetGroup.NodeStatus.Pending));
    }

    // -------------------------------------------------------------------------
    // createGroup — error cases
    // -------------------------------------------------------------------------

    function testCreateGroup_BelowMinDelay() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        vm.expectRevert("removal delay too short");
        factory.createGroup(addrs, 1, 1 days - 1, 1 days, 1 days, _noIssuers);
    }

    function testCreateGroup_ThresholdTooHigh() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        // threshold=3, length=3 → need length > threshold → should revert
        vm.expectRevert("threshold too high for node count");
        factory.createGroup(addrs, 3, 1 days, 1 days, 1 days, _noIssuers);
    }

    function testCreateGroup_UnregisteredNode() public {
        vm.prank(node1); factory.registerNode(pubkey1, true);
        // node2 and node3 not registered

        address[] memory addrs = new address[](2);
        addrs[0] = node1; addrs[1] = node2;

        vm.expectRevert("node not registered");
        factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);
    }

    // -------------------------------------------------------------------------
    // upgradeGroupImplementation
    // -------------------------------------------------------------------------

    function testUpgradeGroupImplementation() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        address group = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);

        // Deploy a new implementation (re-use SignetGroup for simplicity)
        SignetGroup newImpl = new SignetGroup();

        vm.prank(admin);
        factory.upgradeGroupImplementation(address(newImpl));

        // Verify beacon now points to the new impl
        address beacon = factory.groupBeacon();
        assertEq(UpgradeableBeacon(beacon).implementation(), address(newImpl));

        // Existing group proxy should still work (same storage, new code)
        assertEq(ISignetGroup(group).getActiveNodes().length, 3);
    }

    function testUpgradeGroupImplementation_NotOwner() public {
        SignetGroup newImpl = new SignetGroup();
        vm.prank(node1);
        vm.expectRevert();  // OwnableUpgradeable emits OwnableUnauthorizedAccount
        factory.upgradeGroupImplementation(address(newImpl));
    }

    // -------------------------------------------------------------------------
    // getNodeGroups / getNodePubkey
    // -------------------------------------------------------------------------

    function testGetNodeGroups_Empty() public {
        assertEq(factory.getNodeGroups(node1).length, 0);
    }

    function testGetNodePubkey() public {
        vm.prank(node1); factory.registerNode(pubkey1, true);
        assertEq(keccak256(factory.getNodePubkey(node1)), keccak256(pubkey1));
    }

    function testGetNodePubkey_NotRegistered() public {
        assertEq(factory.getNodePubkey(node1).length, 0);
    }

    // -------------------------------------------------------------------------
    // nodeActivated / nodeDeactivated callbacks
    // -------------------------------------------------------------------------

    function testNodeActivated_OnCreateGroup() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        address group = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);

        address[] memory g1 = factory.getNodeGroups(node1);
        assertEq(g1.length, 1);
        assertEq(g1[0], group);

        address[] memory g2 = factory.getNodeGroups(node2);
        assertEq(g2.length, 1);
        assertEq(g2[0], group);
    }

    function testNodeActivated_NotGroup() public {
        vm.expectRevert("not a group");
        factory.nodeActivated(node1);
    }

    function testNodeDeactivated_OnRemoval() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        address group = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);

        assertEq(factory.getNodeGroups(node1).length, 1);

        // address(this) is the manager; queue and execute removal of node1
        ISignetGroup(group).queueRemoval(node1);
        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, true, false, false);
        emit ISignetFactory.NodeDeactivatedInGroup(node1, group);
        ISignetGroup(group).executeRemoval(node1);

        assertEq(factory.getNodeGroups(node1).length, 0);
        // other nodes still tracked
        assertEq(factory.getNodeGroups(node2).length, 1);
    }

    function testNodeDeactivated_NotGroup() public {
        vm.expectRevert("not a group");
        factory.nodeDeactivated(node1);
    }

    function testNodeGroups_MultipleGroups() public {
        _registerAll();
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        address group1 = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);
        address group2 = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);

        address[] memory groups1 = factory.getNodeGroups(node1);
        assertEq(groups1.length, 2);
        // both groups present
        bool foundG1;
        bool foundG2;
        for (uint i = 0; i < groups1.length; i++) {
            if (groups1[i] == group1) foundG1 = true;
            if (groups1[i] == group2) foundG2 = true;
        }
        assertTrue(foundG1);
        assertTrue(foundG2);
    }
}
