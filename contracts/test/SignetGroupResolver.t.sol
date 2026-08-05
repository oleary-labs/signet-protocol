// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../contracts/SignetFactory.sol";
import "../contracts/SignetGroup.sol";
import "../contracts/interfaces/ISignetFactory.sol";
import "../contracts/interfaces/ISignetGroup.sol";
import "./mocks/MockAuthResolver.sol";

/// @dev Exercises the timelocked on-chain auth-resolver binding on SignetGroup,
///      mirroring the node-removal timelock test patterns.
contract SignetGroupResolverTest is Test {
    SignetFactory factory;
    SignetGroup   groupImpl;
    MockAuthResolver resolver;

    uint256 constant PK1 = 0x1111;
    uint256 constant PK2 = 0x2222;
    uint256 constant PK3 = 0x3333;

    address node1; address node2; address node3;

    address admin    = address(0xAD);
    address manager  = address(0x1337);
    address stranger = address(0xBEEF);

    uint64  constant CHAIN_ID = 8453;
    bool    constant REQ_SUBJECT = true;

    ISignetGroup.InitialIssuer[] internal _noIssuers;
    bytes[] internal _noAuthKeys;

    function _uncompressedPubkey(uint256 privKey) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(privKey);
        return abi.encodePacked(bytes1(0x04), bytes32(w.publicKeyX), bytes32(w.publicKeyY));
    }

    function setUp() public {
        node1 = vm.addr(PK1);
        node2 = vm.addr(PK2);
        node3 = vm.addr(PK3);

        groupImpl = new SignetGroup();
        SignetFactory factoryImpl = new SignetFactory();
        bytes memory initData = abi.encodeCall(
            SignetFactory.initialize,
            (admin, address(groupImpl))
        );
        factory = SignetFactory(address(new ERC1967Proxy(address(factoryImpl), initData)));

        vm.prank(node1); factory.registerNode(_uncompressedPubkey(PK1), true, address(0));
        vm.prank(node2); factory.registerNode(_uncompressedPubkey(PK2), true, address(0));
        vm.prank(node3); factory.registerNode(_uncompressedPubkey(PK3), true, address(0));

        resolver = new MockAuthResolver();
    }

    function _group() internal returns (ISignetGroup) {
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        vm.prank(manager);
        return ISignetGroup(factory.createGroup(addrs, 2, 1 days, _noIssuers, _noAuthKeys));
    }

    // -------------------------------------------------------------------------
    // Default state
    // -------------------------------------------------------------------------

    function testDefaultResolverIsUnset() public {
        ISignetGroup g = _group();
        ISignetGroup.AuthResolver memory r = g.getAuthResolver();
        assertEq(r.resolver, address(0));
        assertEq(r.chainId, 0);
        assertEq(r.requireCanonicalSubject, false);
        assertEq(g.getPendingAuthResolver().executeAfter, 0);
    }

    // -------------------------------------------------------------------------
    // Queue → execute happy path
    // -------------------------------------------------------------------------

    function testQueueAndExecuteAuthResolver() public {
        ISignetGroup g = _group();

        uint256 expectedAfter = block.timestamp + 1 days;
        vm.prank(manager);
        vm.expectEmit(true, false, false, true);
        emit ISignetGroup.AuthResolverQueued(CHAIN_ID, address(resolver), REQ_SUBJECT, expectedAfter);
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);

        // Not yet active.
        assertEq(g.getAuthResolver().resolver, address(0));
        ISignetGroup.PendingResolver memory p = g.getPendingAuthResolver();
        assertEq(p.executeAfter, expectedAfter);
        assertEq(p.next.resolver, address(resolver));
        assertEq(p.initiator, manager);

        // Cannot execute before delay.
        vm.expectRevert("delay not elapsed");
        g.executeAuthResolver();

        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, true);
        emit ISignetGroup.AuthResolverSet(CHAIN_ID, address(resolver), REQ_SUBJECT);
        g.executeAuthResolver(); // permissionless

        ISignetGroup.AuthResolver memory r = g.getAuthResolver();
        assertEq(r.chainId, CHAIN_ID);
        assertEq(r.resolver, address(resolver));
        assertEq(r.requireCanonicalSubject, REQ_SUBJECT);
        // Pending cleared.
        assertEq(g.getPendingAuthResolver().executeAfter, 0);
    }

    // -------------------------------------------------------------------------
    // Access control + guards
    // -------------------------------------------------------------------------

    function testQueue_OnlyManager() public {
        ISignetGroup g = _group();
        vm.prank(stranger);
        vm.expectRevert("not manager");
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);
    }

    function testQueue_RejectsDoubleQueue() public {
        ISignetGroup g = _group();
        vm.startPrank(manager);
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);
        vm.expectRevert("resolver change already queued");
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);
        vm.stopPrank();
    }

    function testQueue_NonZeroResolverRequiresChainId() public {
        ISignetGroup g = _group();
        vm.prank(manager);
        vm.expectRevert("chainId required");
        g.queueAuthResolver(0, address(resolver), false);
    }

    function testQueue_ClearMustBeZeroed() public {
        ISignetGroup g = _group();
        vm.prank(manager);
        vm.expectRevert("clear must be zeroed");
        g.queueAuthResolver(CHAIN_ID, address(0), false);
    }

    // -------------------------------------------------------------------------
    // Cancel
    // -------------------------------------------------------------------------

    function testCancel_ByInitiator() public {
        ISignetGroup g = _group();
        vm.prank(manager);
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);

        vm.prank(manager);
        vm.expectEmit(true, false, false, false);
        emit ISignetGroup.AuthResolverCancelled(manager);
        g.cancelAuthResolver();

        assertEq(g.getPendingAuthResolver().executeAfter, 0);
        assertEq(g.getAuthResolver().resolver, address(0));
    }

    function testCancel_NotInitiator() public {
        ISignetGroup g = _group();
        vm.prank(manager);
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);

        vm.prank(stranger);
        vm.expectRevert("not initiator");
        g.cancelAuthResolver();
    }

    function testCancel_NothingQueued() public {
        ISignetGroup g = _group();
        vm.prank(manager);
        vm.expectRevert("no queued resolver change");
        g.cancelAuthResolver();
    }

    function testExecute_NothingQueued() public {
        ISignetGroup g = _group();
        vm.expectRevert("no queued resolver change");
        g.executeAuthResolver();
    }

    // -------------------------------------------------------------------------
    // Clearing an active resolver (queue zeroed change after one is set)
    // -------------------------------------------------------------------------

    function testClearActiveResolver() public {
        ISignetGroup g = _group();

        // Set one.
        vm.prank(manager);
        g.queueAuthResolver(CHAIN_ID, address(resolver), REQ_SUBJECT);
        vm.warp(block.timestamp + 1 days);
        g.executeAuthResolver();
        assertEq(g.getAuthResolver().resolver, address(resolver));

        // Queue a clear.
        vm.prank(manager);
        g.queueAuthResolver(0, address(0), false);
        vm.warp(block.timestamp + 1 days);
        g.executeAuthResolver();

        assertEq(g.getAuthResolver().resolver, address(0));
        assertEq(g.getAuthResolver().chainId, 0);
    }
}
