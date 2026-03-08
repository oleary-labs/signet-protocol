// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../contracts/SignetFactory.sol";
import "../contracts/SignetGroup.sol";
import "../contracts/interfaces/ISignetFactory.sol";
import "../contracts/interfaces/ISignetGroup.sol";

/// @dev Shared helpers (mirrors SignetFactory.t.sol)
abstract contract PubkeyHelpersGroup is Test {
    function _uncompressedPubkey(uint256 privKey) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(privKey);
        return abi.encodePacked(bytes1(0x04), bytes32(w.publicKeyX), bytes32(w.publicKeyY));
    }
}

contract SignetGroupTest is PubkeyHelpersGroup {
    SignetFactory factory;
    SignetGroup   groupImpl;

    uint256 constant PK1 = 0x1111;
    uint256 constant PK2 = 0x2222;
    uint256 constant PK3 = 0x3333;
    uint256 constant PK4 = 0x4444;

    address node1; address node2; address node3; address node4;
    bytes   pub1;  bytes   pub2;  bytes   pub3;  bytes   pub4;

    address admin   = address(0xAD);
    address manager = address(0x1337);

    function setUp() public {
        node1 = vm.addr(PK1); pub1 = _uncompressedPubkey(PK1);
        node2 = vm.addr(PK2); pub2 = _uncompressedPubkey(PK2);
        node3 = vm.addr(PK3); pub3 = _uncompressedPubkey(PK3);
        node4 = vm.addr(PK4); pub4 = _uncompressedPubkey(PK4);

        groupImpl = new SignetGroup();
        SignetFactory factoryImpl = new SignetFactory();
        bytes memory initData = abi.encodeCall(
            SignetFactory.initialize,
            (admin, address(groupImpl))
        );
        factory = SignetFactory(address(new ERC1967Proxy(address(factoryImpl), initData)));

        // Register all nodes as open by default
        vm.prank(node1); factory.registerNode(pub1, true);
        vm.prank(node2); factory.registerNode(pub2, true);
        vm.prank(node3); factory.registerNode(pub3, true);
        vm.prank(node4); factory.registerNode(pub4, true);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    ISignetGroup.InitialIssuer[] internal _noIssuers;

    /// @dev Creates a group with the given set; threshold=1, 1-day delays; manager=this.manager.
    function _createGroup(address[] memory addrs) internal returns (ISignetGroup) {
        vm.prank(manager);
        address g = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);
        return ISignetGroup(g);
    }

    function _threeNodeGroup() internal returns (ISignetGroup) {
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        return _createGroup(addrs);
    }

    // -------------------------------------------------------------------------
    // Open node auto-active on creation
    // -------------------------------------------------------------------------

    function testOpenNodeJoinsImmediately() public {
        ISignetGroup g = _threeNodeGroup();
        assertEq(g.getActiveNodes().length, 3);
        assertEq(uint8(g.nodeStatus(node1)), uint8(ISignetGroup.NodeStatus.Active));
        assertEq(uint8(g.nodeStatus(node2)), uint8(ISignetGroup.NodeStatus.Active));
        assertEq(uint8(g.nodeStatus(node3)), uint8(ISignetGroup.NodeStatus.Active));
    }

    // -------------------------------------------------------------------------
    // Permissioned (non-open) node → Pending
    // -------------------------------------------------------------------------

    function testPermissionedNodePending() public {
        // Make node2 non-open
        vm.prank(node2); factory.updateOpenStatus(false);

        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        ISignetGroup g = _createGroup(addrs);

        assertEq(g.getActiveNodes().length, 2);
        assertEq(g.getPendingNodes().length, 1);
        assertEq(uint8(g.nodeStatus(node2)), uint8(ISignetGroup.NodeStatus.Pending));
    }

    // -------------------------------------------------------------------------
    // acceptInvite
    // -------------------------------------------------------------------------

    function testAcceptInvite() public {
        vm.prank(node2); factory.updateOpenStatus(false);

        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        ISignetGroup g = _createGroup(addrs);

        vm.prank(node2);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.NodeJoined(node2);
        g.acceptInvite();

        assertEq(g.getActiveNodes().length, 3);
        assertEq(g.getPendingNodes().length, 0);
        assertEq(uint8(g.nodeStatus(node2)), uint8(ISignetGroup.NodeStatus.Active));
    }

    function testOnlyNodeCanAccept() public {
        vm.prank(node2); factory.updateOpenStatus(false);
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        ISignetGroup g = _createGroup(addrs);

        // node1 is not pending — cannot accept
        vm.prank(node1);
        vm.expectRevert("not pending");
        g.acceptInvite();
    }

    // -------------------------------------------------------------------------
    // declineInvite
    // -------------------------------------------------------------------------

    function testDeclineInvite() public {
        vm.prank(node2); factory.updateOpenStatus(false);
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        ISignetGroup g = _createGroup(addrs);

        vm.prank(node2);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.NodeDeclined(node2);
        g.declineInvite();

        assertEq(g.getPendingNodes().length, 0);
        assertEq(uint8(g.nodeStatus(node2)), uint8(ISignetGroup.NodeStatus.None));
    }

    // -------------------------------------------------------------------------
    // inviteNode (post-creation, manager-only)
    // -------------------------------------------------------------------------

    function testInviteNode_OpenNode() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(manager);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.NodeJoined(node4);
        g.inviteNode(node4);

        assertEq(g.getActiveNodes().length, 4);
    }

    function testInviteNode_PermissionedNode() public {
        vm.prank(node4); factory.updateOpenStatus(false);
        ISignetGroup g = _threeNodeGroup();

        vm.prank(manager);
        g.inviteNode(node4);

        assertEq(uint8(g.nodeStatus(node4)), uint8(ISignetGroup.NodeStatus.Pending));
    }

    function testOnlyManagerCanInvite() public {
        ISignetGroup g = _threeNodeGroup();
        vm.prank(node1);
        vm.expectRevert("not manager");
        g.inviteNode(node4);
    }

    // -------------------------------------------------------------------------
    // queueRemoval + executeRemoval — manager-initiated
    // -------------------------------------------------------------------------

    function testQueueAndExecuteRemoval_Manager() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(manager);
        uint256 expectedAfter = block.timestamp + 1 days;
        vm.expectEmit(true, true, false, true);
        emit ISignetGroup.RemovalQueued(node1, manager, expectedAfter);
        g.queueRemoval(node1);

        // Cannot execute before delay
        vm.expectRevert("delay not elapsed");
        g.executeRemoval(node1);

        // Advance time past delay
        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.NodeRemoved(node1);
        g.executeRemoval(node1);

        assertEq(g.getActiveNodes().length, 2);
        assertEq(uint8(g.nodeStatus(node1)), uint8(ISignetGroup.NodeStatus.None));
    }

    function testQueueAndExecuteRemoval_SelfInitiated() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(node2);
        g.queueRemoval(node2);

        vm.warp(block.timestamp + 1 days);
        g.executeRemoval(node2);

        assertEq(g.getActiveNodes().length, 2);
    }

    function testExecuteRemoval_TooEarly() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(manager);
        g.queueRemoval(node1);

        vm.warp(block.timestamp + 1 days - 1);
        vm.expectRevert("delay not elapsed");
        g.executeRemoval(node1);
    }

    // -------------------------------------------------------------------------
    // cancelRemoval
    // -------------------------------------------------------------------------

    function testCancelRemoval_ByManager() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(node1);
        g.queueRemoval(node1);  // self-initiated

        vm.prank(manager);
        vm.expectEmit(true, true, false, false);
        emit ISignetGroup.RemovalCancelled(node1, manager);
        g.cancelRemoval(node1);

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert("no queued removal");
        g.executeRemoval(node1);
    }

    function testCancelRemoval_ByInitiator() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(node1);
        g.queueRemoval(node1);  // self-initiated

        vm.prank(node1);
        g.cancelRemoval(node1);

        // Request is gone
        ISignetGroup.RemovalRequest memory req = g.removalRequests(node1);
        assertEq(req.executeAfter, 0);
    }

    function testCancelRemoval_NotManagerOrInitiator() public {
        ISignetGroup g = _threeNodeGroup();
        vm.prank(manager); g.queueRemoval(node1);

        vm.prank(node2);
        vm.expectRevert("not manager or initiator");
        g.cancelRemoval(node1);
    }

    // -------------------------------------------------------------------------
    // transferManager
    // -------------------------------------------------------------------------

    function testTransferManager() public {
        ISignetGroup g = _threeNodeGroup();
        address newMgr = address(0xBEEF);

        vm.prank(manager);
        vm.expectEmit(true, true, false, false);
        emit ISignetGroup.ManagerTransferred(manager, newMgr);
        g.transferManager(newMgr);

        assertEq(g.manager(), newMgr);

        // Old manager loses access
        vm.prank(manager);
        vm.expectRevert("not manager");
        g.inviteNode(node4);

        // New manager works
        vm.prank(newMgr);
        g.inviteNode(node4);
    }

    // -------------------------------------------------------------------------
    // getActiveNodes after multiple adds/removes
    // -------------------------------------------------------------------------

    function testGetActiveNodes() public {
        ISignetGroup g = _threeNodeGroup();

        // Remove middle node (node2) and verify swap-and-pop correctness
        vm.prank(manager); g.queueRemoval(node2);
        vm.warp(block.timestamp + 1 days);
        g.executeRemoval(node2);

        address[] memory active = g.getActiveNodes();
        assertEq(active.length, 2);
        // node2 must not be in the list
        for (uint256 i = 0; i < active.length; i++) {
            assertTrue(active[i] != node2);
        }

        // Add node4
        vm.prank(manager); g.inviteNode(node4);
        assertEq(g.getActiveNodes().length, 3);
    }

    // -------------------------------------------------------------------------
    // isOperational
    // -------------------------------------------------------------------------

    function testIsOperational() public {
        // threshold=1 → quorum=2; start with 3 → operational
        ISignetGroup g = _threeNodeGroup();
        assertTrue(g.isOperational());

        // Remove two nodes → 1 active < 2 quorum → not operational
        vm.prank(manager); g.queueRemoval(node1);
        vm.prank(manager); g.queueRemoval(node2);
        vm.warp(block.timestamp + 1 days);
        g.executeRemoval(node1);
        g.executeRemoval(node2);

        assertFalse(g.isOperational());
    }

    // -------------------------------------------------------------------------
    // getPendingRemovals
    // -------------------------------------------------------------------------

    function testGetPendingRemovals() public {
        ISignetGroup g = _threeNodeGroup();
        assertEq(g.getPendingRemovals().length, 0);

        vm.prank(manager); g.queueRemoval(node1);
        vm.prank(manager); g.queueRemoval(node3);

        address[] memory pending = g.getPendingRemovals();
        assertEq(pending.length, 2);
    }

    // -------------------------------------------------------------------------
    // quorum
    // -------------------------------------------------------------------------

    function testQuorum() public {
        ISignetGroup g = _threeNodeGroup();
        assertEq(g.quorum(), 2);  // threshold=1 → quorum=2
    }

    // -------------------------------------------------------------------------
    // Factory callbacks: nodeActivated / nodeDeactivated
    // -------------------------------------------------------------------------

    function testNodeJoined_FiresFactoryCallback() public {
        ISignetGroup g = _threeNodeGroup();

        // All three open nodes are active → factory should track them in their nodeGroups
        address[] memory groups1 = factory.getNodeGroups(node1);
        assertEq(groups1.length, 1);
        assertEq(groups1[0], address(g));

        address[] memory groups2 = factory.getNodeGroups(node2);
        assertEq(groups2.length, 1);
        assertEq(groups2[0], address(g));

        address[] memory groups3 = factory.getNodeGroups(node3);
        assertEq(groups3.length, 1);
        assertEq(groups3[0], address(g));
    }

    function testNodeRemoved_FiresFactoryCallback() public {
        ISignetGroup g = _threeNodeGroup();

        vm.prank(manager);
        g.queueRemoval(node1);
        vm.warp(block.timestamp + 1 days);
        g.executeRemoval(node1);

        // node1 should no longer be tracked in factory
        assertEq(factory.getNodeGroups(node1).length, 0);
        // node2 and node3 still tracked
        assertEq(factory.getNodeGroups(node2).length, 1);
        assertEq(factory.getNodeGroups(node3).length, 1);
    }

    function testAcceptInvite_FiresFactoryCallback() public {
        vm.prank(node2); factory.updateOpenStatus(false);

        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        ISignetGroup g = _createGroup(addrs);

        // node2 is pending → not yet in factory nodeGroups
        assertEq(factory.getNodeGroups(node2).length, 0);

        vm.prank(node2);
        g.acceptInvite();

        // now active → factory should track it
        address[] memory groups2 = factory.getNodeGroups(node2);
        assertEq(groups2.length, 1);
        assertEq(groups2[0], address(g));
    }
}

// =============================================================================
// Issuer management tests
// =============================================================================

contract SignetGroupIssuerTest is PubkeyHelpersGroup {
    SignetFactory factory;
    SignetGroup   groupImpl;

    uint256 constant PK1 = 0x1111;
    uint256 constant PK2 = 0x2222;
    uint256 constant PK3 = 0x3333;

    address node1; address node2; address node3;
    bytes   pub1;  bytes   pub2;  bytes   pub3;

    address admin   = address(0xAD);
    address manager = address(0x1337);

    string constant ISS1 = "https://accounts.google.com";
    string constant ISS2 = "https://auth.example.com";
    string constant CLIENT_A = "client-abc";
    string constant CLIENT_B = "client-xyz";

    bytes32 immutable HASH1 = keccak256(abi.encodePacked(ISS1));
    bytes32 immutable HASH2 = keccak256(abi.encodePacked(ISS2));

    function setUp() public {
        node1 = vm.addr(PK1); pub1 = _uncompressedPubkey(PK1);
        node2 = vm.addr(PK2); pub2 = _uncompressedPubkey(PK2);
        node3 = vm.addr(PK3); pub3 = _uncompressedPubkey(PK3);

        groupImpl = new SignetGroup();
        SignetFactory factoryImpl = new SignetFactory();
        bytes memory initData = abi.encodeCall(
            SignetFactory.initialize,
            (admin, address(groupImpl))
        );
        factory = SignetFactory(address(new ERC1967Proxy(address(factoryImpl), initData)));

        vm.prank(node1); factory.registerNode(pub1, true);
        vm.prank(node2); factory.registerNode(pub2, true);
        vm.prank(node3); factory.registerNode(pub3, true);
    }

    ISignetGroup.InitialIssuer[] internal _noIssuers;

    function _makeGroup() internal returns (ISignetGroup) {
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        vm.prank(manager);
        address g = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, _noIssuers);
        return ISignetGroup(g);
    }

    function _makeGroupWithIssuer() internal returns (ISignetGroup) {
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;

        ISignetGroup.InitialIssuer[] memory issuers = new ISignetGroup.InitialIssuer[](1);
        string[] memory cids = new string[](2);
        cids[0] = CLIENT_A; cids[1] = CLIENT_B;
        issuers[0] = ISignetGroup.InitialIssuer({ issuer: ISS1, clientIds: cids });

        vm.prank(manager);
        address g = factory.createGroup(addrs, 1, 1 days, 1 days, 1 days, issuers);
        return ISignetGroup(g);
    }

    // -------------------------------------------------------------------------
    // Initial issuers at creation (no delay)
    // -------------------------------------------------------------------------

    function testInitialIssuerAddedAtCreation() public {
        ISignetGroup g = _makeGroupWithIssuer();
        ISignetGroup.OAuthIssuer[] memory issuers = g.getIssuers();
        assertEq(issuers.length, 1);
        assertEq(issuers[0].issuer, ISS1);
        assertEq(issuers[0].clientIds.length, 2);
        assertEq(issuers[0].clientIds[0], CLIENT_A);
        assertEq(issuers[0].clientIds[1], CLIENT_B);
    }

    // -------------------------------------------------------------------------
    // queueAddIssuer / executeAddIssuer
    // -------------------------------------------------------------------------

    function testQueueAndExecuteAddIssuer() public {
        ISignetGroup g = _makeGroup();
        assertEq(g.getIssuers().length, 0);

        string[] memory cids = new string[](1);
        cids[0] = CLIENT_A;

        vm.prank(manager);
        uint256 expectedAfter = block.timestamp + 1 days;
        vm.expectEmit(true, false, false, true);
        emit ISignetGroup.IssuerAddQueued(HASH1, ISS1, cids, expectedAfter);
        g.queueAddIssuer(ISS1, cids);

        // Cannot execute before delay
        vm.expectRevert("delay not elapsed");
        g.executeAddIssuer(HASH1);

        vm.warp(block.timestamp + 1 days);
        vm.expectEmit(true, false, false, true);
        emit ISignetGroup.IssuerAdded(HASH1, ISS1, cids);
        g.executeAddIssuer(HASH1);

        ISignetGroup.OAuthIssuer[] memory issuers = g.getIssuers();
        assertEq(issuers.length, 1);
        assertEq(issuers[0].issuer, ISS1);
    }

    // -------------------------------------------------------------------------
    // cancelAddIssuer
    // -------------------------------------------------------------------------

    function testCancelAddIssuer() public {
        ISignetGroup g = _makeGroup();

        string[] memory cids = new string[](1);
        cids[0] = CLIENT_A;

        vm.prank(manager);
        g.queueAddIssuer(ISS1, cids);

        vm.prank(manager);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.IssuerAddCancelled(HASH1);
        g.cancelAddIssuer(HASH1);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert("not pending");
        g.executeAddIssuer(HASH1);

        assertEq(g.getIssuers().length, 0);
    }

    // -------------------------------------------------------------------------
    // Duplicate add guard
    // -------------------------------------------------------------------------

    function testDuplicateAddIssuerReverts() public {
        ISignetGroup g = _makeGroupWithIssuer();

        // ISS1 is already active; trying to queue it again should revert
        string[] memory cids = new string[](1);
        cids[0] = CLIENT_A;
        vm.prank(manager);
        vm.expectRevert("issuer already exists");
        g.queueAddIssuer(ISS1, cids);
    }

    // -------------------------------------------------------------------------
    // queueRemoveIssuer / executeRemoveIssuer
    // -------------------------------------------------------------------------

    function testQueueAndExecuteRemoveIssuer() public {
        ISignetGroup g = _makeGroupWithIssuer();
        assertEq(g.getIssuers().length, 1);

        vm.prank(manager);
        uint256 expectedAfter = block.timestamp + 1 days;
        vm.expectEmit(true, false, false, true);
        emit ISignetGroup.IssuerRemovalQueued(HASH1, expectedAfter);
        g.queueRemoveIssuer(HASH1);

        // Cannot execute before delay
        vm.expectRevert("delay not elapsed");
        g.executeRemoveIssuer(HASH1);

        vm.warp(block.timestamp + 1 days);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.IssuerRemoved(HASH1, ISS1);
        g.executeRemoveIssuer(HASH1);

        assertEq(g.getIssuers().length, 0);
    }

    // -------------------------------------------------------------------------
    // cancelRemoveIssuer
    // -------------------------------------------------------------------------

    function testCancelRemoveIssuer() public {
        ISignetGroup g = _makeGroupWithIssuer();

        vm.prank(manager);
        g.queueRemoveIssuer(HASH1);

        vm.prank(manager);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.IssuerRemovalCancelled(HASH1);
        g.cancelRemoveIssuer(HASH1);

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert("no queued removal");
        g.executeRemoveIssuer(HASH1);

        // Issuer still present
        assertEq(g.getIssuers().length, 1);
    }

    // -------------------------------------------------------------------------
    // Remove before delay reverts
    // -------------------------------------------------------------------------

    function testRemoveBeforeDelayReverts() public {
        ISignetGroup g = _makeGroupWithIssuer();

        vm.prank(manager);
        g.queueRemoveIssuer(HASH1);

        vm.warp(block.timestamp + 1 days - 1);
        vm.expectRevert("delay not elapsed");
        g.executeRemoveIssuer(HASH1);
    }

    // -------------------------------------------------------------------------
    // getIssuers view — multiple issuers, swap-and-pop correctness
    // -------------------------------------------------------------------------

    function testGetIssuers_MultipleAndSwapPop() public {
        ISignetGroup g = _makeGroup();

        string[] memory cids1 = new string[](1); cids1[0] = CLIENT_A;
        string[] memory cids2 = new string[](1); cids2[0] = CLIENT_B;

        vm.startPrank(manager);
        g.queueAddIssuer(ISS1, cids1);
        g.queueAddIssuer(ISS2, cids2);
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days);
        g.executeAddIssuer(HASH1);
        g.executeAddIssuer(HASH2);

        ISignetGroup.OAuthIssuer[] memory issuers = g.getIssuers();
        assertEq(issuers.length, 2);

        // Remove first issuer (tests swap-and-pop)
        vm.prank(manager);
        g.queueRemoveIssuer(HASH1);
        vm.warp(block.timestamp + 1 days);
        g.executeRemoveIssuer(HASH1);

        issuers = g.getIssuers();
        assertEq(issuers.length, 1);
        assertEq(issuers[0].issuer, ISS2);
    }

    // -------------------------------------------------------------------------
    // isClientIdTrusted view
    // -------------------------------------------------------------------------

    function testIsClientIdTrusted() public {
        ISignetGroup g = _makeGroupWithIssuer();

        assertTrue(g.isClientIdTrusted(HASH1, CLIENT_A));
        assertTrue(g.isClientIdTrusted(HASH1, CLIENT_B));
        assertFalse(g.isClientIdTrusted(HASH1, "unknown-client"));
        assertFalse(g.isClientIdTrusted(HASH2, CLIENT_A)); // HASH2 not registered
    }

    // -------------------------------------------------------------------------
    // Access control: only manager can queue/cancel
    // -------------------------------------------------------------------------

    function testOnlyManagerCanQueueAddIssuer() public {
        ISignetGroup g = _makeGroup();
        string[] memory cids = new string[](0);
        vm.prank(node1);
        vm.expectRevert("not manager");
        g.queueAddIssuer(ISS1, cids);
    }

    function testOnlyManagerCanQueueRemoveIssuer() public {
        ISignetGroup g = _makeGroupWithIssuer();
        vm.prank(node1);
        vm.expectRevert("not manager");
        g.queueRemoveIssuer(HASH1);
    }
}
