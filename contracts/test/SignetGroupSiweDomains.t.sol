// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../contracts/SignetFactory.sol";
import "../contracts/SignetGroup.sol";
import "../contracts/interfaces/ISignetGroup.sol";

/// @notice SIWE domain list: lifecycle, and the canonical-form rule.
///
/// The canonicalization cases matter more than they look. The node applies the
/// same rule in Go, and a disagreement between the two implementations is worse
/// than a wildcard would be: it fails intermittently, some nodes accepting a
/// session while others reject it, so the group never reaches threshold and the
/// error points nowhere. These cases are the shared definition.
contract SignetGroupSiweDomainsTest is Test {
    SignetFactory factory;
    SignetGroup   groupImpl;

    uint256 constant PK1 = 0x1111;
    uint256 constant PK2 = 0x2222;
    uint256 constant PK3 = 0x3333;

    address node1; address node2; address node3;

    address admin   = address(0xAD);
    address manager = address(0x1337);
    address rando   = address(0xBEEF);

    uint256 constant DELAY = 1 days;

    ISignetGroup.InitialIssuer[] internal _noIssuers;
    bytes[] internal _noAuthKeys;

    function setUp() public {
        node1 = vm.addr(PK1);
        node2 = vm.addr(PK2);
        node3 = vm.addr(PK3);

        groupImpl = new SignetGroup();
        SignetFactory factoryImpl = new SignetFactory();
        factory = SignetFactory(address(new ERC1967Proxy(
            address(factoryImpl),
            abi.encodeCall(SignetFactory.initialize, (admin, address(groupImpl)))
        )));

        Vm.Wallet memory w1 = vm.createWallet(PK1);
        Vm.Wallet memory w2 = vm.createWallet(PK2);
        Vm.Wallet memory w3 = vm.createWallet(PK3);

        vm.prank(node1);
        factory.registerNode(abi.encodePacked(bytes1(0x04), w1.publicKeyX, w1.publicKeyY), true, address(0));
        vm.prank(node2);
        factory.registerNode(abi.encodePacked(bytes1(0x04), w2.publicKeyX, w2.publicKeyY), true, address(0));
        vm.prank(node3);
        factory.registerNode(abi.encodePacked(bytes1(0x04), w3.publicKeyX, w3.publicKeyY), true, address(0));
    }

    function _makeGroup() internal returns (ISignetGroup) {
        address[] memory addrs = new address[](3);
        addrs[0] = node1; addrs[1] = node2; addrs[2] = node3;
        vm.prank(manager);
        return ISignetGroup(factory.createGroup(addrs, 1, DELAY, _noIssuers, _noAuthKeys));
    }

    function _one(string memory d) internal pure returns (string[] memory out) {
        out = new string[](1);
        out[0] = d;
    }

    /// @dev Advance past one timelock.
    ///
    ///      Reads the timestamp via the cheatcode rather than `block.timestamp`.
    ///      foundry.toml sets via_ir, and the optimizer treats TIMESTAMP as pure
    ///      and folds it across the vm.warp call — so a second
    ///      `vm.warp(block.timestamp + DELAY)` in the same function re-uses the
    ///      value from before the first warp and silently does not advance. That
    ///      shows up as "delay not elapsed" on the second execute and looks like
    ///      a contract bug.
    function _advance() internal {
        vm.warp(vm.getBlockTimestamp() + DELAY);
    }

    // ---------- lifecycle ----------

    // Empty is the default and must stay meaning "disabled", never "any domain".
    function testDefaultListIsEmpty() public {
        ISignetGroup g = _makeGroup();
        assertEq(g.siweDomains().length, 0);
    }

    function testQueueThenExecuteSetsList() public {
        ISignetGroup g = _makeGroup();
        string[] memory d = new string[](2);
        d[0] = "app.example.org";
        d[1] = "admin.example.org";

        vm.prank(manager);
        g.queueSiweDomains(d);

        // Not applied until the delay elapses.
        assertEq(g.siweDomains().length, 0);

        _advance();
        g.executeSiweDomains(); // permissionless, like executeAuthResolver

        string[] memory got = g.siweDomains();
        assertEq(got.length, 2);
        assertEq(got[0], "app.example.org");
        assertEq(got[1], "admin.example.org");
    }

    function testExecuteBeforeDelayReverts() public {
        ISignetGroup g = _makeGroup();
        vm.prank(manager);
        g.queueSiweDomains(_one("app.example.org"));

        vm.expectRevert("delay not elapsed");
        g.executeSiweDomains();
    }

    function testOnlyManagerCanQueue() public {
        ISignetGroup g = _makeGroup();
        vm.prank(rando);
        vm.expectRevert();
        g.queueSiweDomains(_one("app.example.org"));
    }

    function testOnlyInitiatorCanCancel() public {
        ISignetGroup g = _makeGroup();
        vm.prank(manager);
        g.queueSiweDomains(_one("app.example.org"));

        vm.prank(rando);
        vm.expectRevert("not initiator");
        g.cancelSiweDomains();

        vm.prank(manager);
        g.cancelSiweDomains();

        // Cancelling clears the queue rather than leaving it executable.
        _advance();
        vm.expectRevert("no queued siwe domain change");
        g.executeSiweDomains();
    }

    // The timelock only buys anything if the pending change can be READ during
    // it. SiweDomainsQueued carries the list, but recovering current pending
    // state from event history means replaying queue/cancel/execute in order —
    // and a cancelled change looks exactly like a live one until you do.
    function testPendingIsReadableThroughItsWholeLifecycle() public {
        ISignetGroup g = _makeGroup();

        (string[] memory d, uint256 ea, address who) = g.getPendingSiweDomains();
        assertEq(d.length, 0);
        assertEq(ea, 0, "nothing pending on a fresh group");
        assertEq(who, address(0));

        vm.prank(manager);
        g.queueSiweDomains(_one("app.example.org"));

        (d, ea, who) = g.getPendingSiweDomains();
        assertEq(d.length, 1);
        assertEq(d[0], "app.example.org", "the queued list is visible before it executes");
        assertEq(ea, vm.getBlockTimestamp() + DELAY);
        assertEq(who, manager);

        // Still readable, and still not applied, right up to the boundary.
        assertEq(g.siweDomains().length, 0);

        _advance();
        g.executeSiweDomains();

        (d, ea, who) = g.getPendingSiweDomains();
        assertEq(d.length, 0, "executing clears the queue");
        assertEq(ea, 0, "executeAfter == 0 is what 'nothing pending' looks like");
        assertEq(who, address(0));
        assertEq(g.siweDomains().length, 1);
    }

    // Cancel must be distinguishable from execute by reading state alone.
    function testPendingClearedOnCancel() public {
        ISignetGroup g = _makeGroup();
        vm.startPrank(manager);
        g.queueSiweDomains(_one("app.example.org"));
        g.cancelSiweDomains();
        vm.stopPrank();

        (string[] memory d, uint256 ea, address who) = g.getPendingSiweDomains();
        assertEq(d.length, 0);
        assertEq(ea, 0);
        assertEq(who, address(0));
        assertEq(g.siweDomains().length, 0, "cancel applies nothing");
    }

    // Replace-wholesale semantics: the new list is the complete future state,
    // not a diff applied to the old one.
    function testExecuteReplacesRatherThanAppends() public {
        ISignetGroup g = _makeGroup();

        string[] memory first = new string[](2);
        first[0] = "a.example.org";
        first[1] = "b.example.org";
        vm.prank(manager);
        g.queueSiweDomains(first);
        _advance();
        g.executeSiweDomains();
        assertEq(g.siweDomains().length, 2);

        vm.prank(manager);
        g.queueSiweDomains(_one("c.example.org"));
        _advance();
        g.executeSiweDomains();

        string[] memory got = g.siweDomains();
        assertEq(got.length, 1);
        assertEq(got[0], "c.example.org");
    }

    // Clearing the list disables the scheme. It must be reachable.
    function testCanClearToEmpty() public {
        ISignetGroup g = _makeGroup();
        vm.prank(manager);
        g.queueSiweDomains(_one("app.example.org"));
        _advance();
        g.executeSiweDomains();

        vm.prank(manager);
        g.queueSiweDomains(new string[](0));
        _advance();
        g.executeSiweDomains();

        assertEq(g.siweDomains().length, 0);
    }

    function testSecondQueueWhilePendingReverts() public {
        ISignetGroup g = _makeGroup();
        vm.startPrank(manager);
        g.queueSiweDomains(_one("a.example.org"));
        vm.expectRevert("siwe domain change already queued");
        g.queueSiweDomains(_one("b.example.org"));
        vm.stopPrank();
    }

    function testDuplicatesRejected() public {
        ISignetGroup g = _makeGroup();
        string[] memory d = new string[](2);
        d[0] = "app.example.org";
        d[1] = "app.example.org";
        vm.prank(manager);
        vm.expectRevert("duplicate domain");
        g.queueSiweDomains(d);
    }

    function testCapEnforced() public {
        ISignetGroup g = _makeGroup();
        string[] memory d = new string[](17); // MAX_SIWE_DOMAINS is 16
        for (uint256 i = 0; i < 17; i++) {
            d[i] = string(abi.encodePacked("d", vm.toString(i), ".example.org"));
        }
        vm.prank(manager);
        vm.expectRevert("too many domains");
        g.queueSiweDomains(d);
    }

    // ---------- canonical form ----------

    function _accepts(string memory d) internal returns (bool ok) {
        ISignetGroup g = _makeGroup();
        vm.prank(manager);
        try g.queueSiweDomains(_one(d)) { ok = true; } catch { ok = false; }
    }

    function testAcceptsCanonicalForms() public {
        assertTrue(_accepts("example.org"),            "bare host");
        assertTrue(_accepts("app.example.org"),        "subdomain");
        assertTrue(_accepts("a-b.example.org"),        "internal hyphen");
        assertTrue(_accepts("localhost"),              "single label");
        assertTrue(_accepts("localhost:3000"),         "explicit dev port");
        assertTrue(_accepts("example.org:65535"),      "max port");
        assertTrue(_accepts("example.org:1"),          "min port");
        assertTrue(_accepts("xn--80ak6aa92e.com"),     "punycode IDN stays representable");
        assertTrue(_accepts("1.example.org"),          "leading digit label");
    }

    function testRejectsNonCanonicalForms() public {
        // Case: Go and Solidity unicode folding will not agree, so the rule is
        // ASCII-lowercase-only and anything else is simply not canonical.
        assertFalse(_accepts("App.example.org"),       "uppercase");
        assertFalse(_accepts("EXAMPLE.ORG"),           "all caps");

        // Not an authority.
        assertFalse(_accepts("https://example.org"),   "scheme");
        assertFalse(_accepts("example.org/path"),      "path");
        assertFalse(_accepts("user@example.org"),      "userinfo");
        assertFalse(_accepts("exa mple.org"),          "whitespace");
        assertFalse(_accepts(""),                      "empty");

        // Wildcards are never patterns here; on a shared suffix they would be
        // catastrophic (anyone can deploy to *.vercel.app).
        assertFalse(_accepts("*.example.org"),         "wildcard");
        assertFalse(_accepts("*"),                     "bare wildcard");

        // Label structure.
        assertFalse(_accepts(".example.org"),          "leading dot");
        assertFalse(_accepts("example.org."),          "trailing dot");
        assertFalse(_accepts("a..example.org"),        "empty label");
        assertFalse(_accepts("-example.org"),          "label starts with hyphen");
        assertFalse(_accepts("example-.org"),          "label ends with hyphen");
        assertFalse(_accepts("example.org-"),          "trailing hyphen");

        // Ports: range-checked, no leading zeros. ":080" would otherwise be a
        // second entry for port 80 that could never match what a browser sends.
        assertFalse(_accepts("example.org:0"),         "port zero");
        assertFalse(_accepts("example.org:65536"),     "port above range");
        assertFalse(_accepts("example.org:99999"),     "port far above range");
        assertFalse(_accepts("example.org:080"),       "leading zero port");
        assertFalse(_accepts("example.org:"),          "trailing colon");
        assertFalse(_accepts("example.org:80a"),       "non-digit in port");
        assertFalse(_accepts("example.org:123456"),    "port too long");
    }

    function testRejectsNonAscii() public {
        // Cyrillic 'а' — a confusable for ASCII 'a'. Excluded by the ASCII rule
        // rather than by a confusables table.
        assertFalse(_accepts(unicode"аpp.example.org"), "cyrillic homoglyph");
        assertFalse(_accepts(unicode"exämple.org"),     "latin-1 supplement");
    }

    function testRejectsOverlongLabelAndHost() public {
        string memory label64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertFalse(_accepts(string(abi.encodePacked(label64, ".org"))), "64-char label");

        // 63 is the boundary and must be accepted.
        string memory label63 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertTrue(_accepts(string(abi.encodePacked(label63, ".org"))), "63-char label");
    }
}
