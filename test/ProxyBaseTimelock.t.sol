// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ProxyBaseTimelock} from "../src/ProxyBaseTimelock.sol";
import "./utils/Implementations.sol";
import {Test, console2} from "forge-std/Test.sol";

contract ProxyBaseTimelockTest is Test {
    uint256 constant TIMELOCK = 24 hours;
    Implementation implementation;
    Implementation proxy;
    uint256 expectedTime;

    function setUp() public {
        implementation = new Implementation();
        proxy = Implementation(address(new ProxyBaseTimelock(address(implementation), address(this), "", TIMELOCK)));
    }

    function test_toggle() public {
        assertFalse(proxy.getFlag(), "Proxy flag should be false 1");
        assertFalse(implementation.getFlag(), "Implementation flag should be false 1");

        proxy.toggle();
        assertTrue(proxy.getFlag(), "Proxy flag should be true");
        assertFalse(implementation.getFlag(), "Implementation flag should be false 2");

        proxy.toggle();
        assertFalse(proxy.getFlag(), "Proxy flag should be false 2");
        assertFalse(implementation.getFlag(), "Implementation flag should be false 3");
    }

    function test_fuzz_calls(bytes4 selector) public {
        vm.assume(
            selector > hex"00000007" && selector != Implementation.toggle.selector
                && selector != Implementation.getFlag.selector
        );

        (bool s, bytes memory returnData) = address(proxy).call(bytes.concat(selector));
        assertFalse(s, "Bad call");
        assertEq(returnData.length, 0, "Wrong returnData length");
    }

    function test_getAndScheduleNewAdmin() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000005");
        assertTrue(s, "Bad getScheduledAdmin call 1");
        ProxyBaseTimelock.NewAdmin memory newAdmin = abi.decode(returnData, (ProxyBaseTimelock.NewAdmin));
        assertEq(newAdmin.admin, address(0), "Wrong scheduled admin 1");
        assertEq(newAdmin.time, type(uint256).max, "Wrong scheduled time 1");

        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        vm.expectEmit(true, false, false, true);
        emit ProxyBaseTimelock.NewAdminScheduled(vm.addr(1), expectedTime);
        bytes memory data = bytes.concat(hex"00000000", abi.encode(vm.addr(1)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewAdmin call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000005");
        assertTrue(s, "Bad getScheduledAdmin call 2");
        newAdmin = abi.decode(returnData, (ProxyBaseTimelock.NewAdmin));
        assertEq(newAdmin.admin, vm.addr(1), "Wrong scheduled admin 2");
        assertEq(newAdmin.time, expectedTime, "Wrong scheduled time 2");

        vm.startPrank(vm.addr(1));
        data = bytes.concat(hex"00000000", abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad scheduleNewAdmin call 2");
        assertEq(
            returnData, abi.encodeWithSelector(ProxyBaseTimelock.NotProxyAdmin.selector, vm.addr(1)), "Wrong returnData"
        );
    }

    function test_getAndChangeAdmin() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000004");
        assertTrue(s, "Bad getAdmin call 1");
        address proxyAdmin = abi.decode(returnData, (address));
        assertEq(proxyAdmin, address(this), "Wrong proxyAdmin 1");

        bytes memory data = hex"00000001";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeAdmin call 1");
        assertEq(returnData, abi.encodeWithSelector(ProxyBaseTimelock.NoAdminScheduled.selector), "Wrong returnData 1");

        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        data = bytes.concat(hex"00000000", abi.encode(vm.addr(1)));
        (s, returnData) = address(proxy).call(data);

        data = hex"00000004";
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad getAdmin call 2");
        proxyAdmin = abi.decode(returnData, (address));
        assertEq(proxyAdmin, address(this), "Wrong proxyAdmin 2");

        data = hex"00000001";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeAdmin call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.Timelocked.selector, expectedTime),
            "Wrong returnData 2"
        );

        vm.warp(expectedTime + 1);
        vm.startPrank(vm.addr(1));
        data = hex"00000001";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeAdmin call 3");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData 3"
        );
        vm.stopPrank();

        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeAdmin call 4");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000005");
        assertTrue(s, "Bad getScheduledAdmin call 1");
        ProxyBaseTimelock.NewAdmin memory newAdmin = abi.decode(returnData, (ProxyBaseTimelock.NewAdmin));
        assertEq(newAdmin.admin, address(0), "Wrong scheduled admin 1");
        assertEq(newAdmin.time, type(uint256).max, "Wrong scheduled time 1");

        (s, returnData) = address(proxy).call(hex"00000004");
        assertTrue(s, "Bad getAdmin call 3");
        proxyAdmin = abi.decode(returnData, (address));
        assertEq(proxyAdmin, vm.addr(1), "Wrong proxyAdmin 3");

        data = bytes.concat(hex"00000000", abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad scheduleNewAdmin call");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.NotProxyAdmin.selector, address(this)),
            "Wrong returnData 4"
        );

        vm.startPrank(vm.addr(1));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        data = bytes.concat(hex"00000000", abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewAdmin call");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000005");
        assertTrue(s, "Bad getScheduledAdmin call 2");
        newAdmin = abi.decode(returnData, (ProxyBaseTimelock.NewAdmin));
        assertEq(newAdmin.admin, vm.addr(2), "Wrong scheduled admin 2");
        assertEq(newAdmin.time, expectedTime, "Wrong scheduled time 2");
        vm.stopPrank();
    }

    function test_getAndScheduleNewImplementation() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000007");
        assertTrue(s, "Bad getScheduledImplementation call 1");
        ProxyBaseTimelock.NewImplementation memory newImplementation =
            abi.decode(returnData, (ProxyBaseTimelock.NewImplementation));
        assertEq(newImplementation.implementation, address(0), "Wrong scheduled implementation 1");
        assertEq(newImplementation.time, type(uint256).max, "Wrong scheduled time 1");
        assertEq(newImplementation.data, "", "Wrong scheduled data 1");

        Implementation3 implementation3 = new Implementation3();
        bytes memory initData = abi.encodeCall(Implementation3.initialize, ("some data"));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        vm.expectEmit(true, false, false, true);
        emit ProxyBaseTimelock.NewImplementationScheduled(address(implementation3), initData, expectedTime);
        bytes memory data = bytes.concat(hex"00000002", abi.encode(address(implementation3), initData));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewImplementation call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000007");
        assertTrue(s, "Bad getScheduledImplementation call 2");
        newImplementation = abi.decode(returnData, (ProxyBaseTimelock.NewImplementation));
        assertEq(newImplementation.implementation, address(implementation3), "Wrong scheduled implementation 2");
        assertEq(newImplementation.time, expectedTime, "Wrong scheduled time 2");
        assertEq(newImplementation.data, initData, "Wrong scheduled data 2");

        vm.startPrank(vm.addr(1));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad getScheduledImplementation call 3");
        assertEq(
            returnData, abi.encodeWithSelector(ProxyBaseTimelock.NotProxyAdmin.selector, vm.addr(1)), "Wrong returnData"
        );
    }

    function test_getAndChangeImplementation() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000006");
        assertTrue(s, "Bad getImplementation call 1");
        address impl = abi.decode(returnData, (address));
        assertEq(impl, address(implementation), "Wrong implementation 1");

        bytes memory data = hex"00000003";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeImplementation call 1");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.NoImplementationScheduled.selector),
            "Wrong returnData 1"
        );

        Implementation3 implementation3 = new Implementation3();
        bytes memory initData = abi.encodeCall(Implementation3.initialize, ("some very long long long long long data"));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        data = bytes.concat(hex"00000002", abi.encode(address(implementation3), initData));
        (s, returnData) = address(proxy).call(data);

        (s, returnData) = address(proxy).call(hex"00000006");
        assertTrue(s, "Bad getImplementation call 2");
        impl = abi.decode(returnData, (address));
        assertEq(impl, address(implementation), "Wrong implementation 2");

        data = hex"00000003";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeImplementation call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.Timelocked.selector, expectedTime),
            "Wrong returnData 2"
        );

        vm.warp(expectedTime + 1);
        vm.startPrank(vm.addr(1));
        data = hex"00000003";
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeImplementation call 3");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelock.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData 3"
        );
        vm.stopPrank();

        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeImplementation call 4");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000007");
        assertTrue(s, "Bad getScheduledImplementation call 1");
        ProxyBaseTimelock.NewImplementation memory newImplementation =
            abi.decode(returnData, (ProxyBaseTimelock.NewImplementation));
        assertEq(newImplementation.implementation, address(0), "Wrong scheduled implementation");
        assertEq(newImplementation.time, type(uint256).max, "Wrong scheduled time");
        assertEq(newImplementation.data, "", "Wrong scheduled data");

        (s, returnData) = address(proxy).call(hex"00000006");
        assertTrue(s, "Bad getImplementation call 3");
        impl = abi.decode(returnData, (address));
        assertEq(impl, address(implementation3), "Wrong implementation 3");

        assertEq(Implementation3(address(proxy)).getData(), "some very long long long long long data", "Wrong data");
    }
}
