// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ProxyBaseTimelockMinimal} from "../src/ProxyBaseTimelockMinimal.sol";
import "./utils/Implementations.sol";
import {Test, console2} from "forge-std/Test.sol";

contract ProxyBaseTimelockMinimalTest is Test {
    bytes32 constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant SCHEDULED_ADMIN_SLOT = 0xf4368cc27f089e2864e7549f41cfcd089cf3dac6a4a45da1e986635a00a9e100;
    bytes32 constant SCHEDULED_IMPLEMENTATION_SLOT = 0x65eefe6fc6d4243074c6129566699e1b26d56abc09f340bdbc9ceb10e6169b00;
    uint256 constant TIMELOCK = 24 hours;
    bytes4 constant SCHEDULE_ADMIN_SELECTOR = 0;
    bytes constant CHANGE_ADMIN_SELECTOR = hex"00000001";
    bytes4 constant SCHEDULE_IMPLEMENTATION_SELECTOR = 0x00000002;
    bytes constant CHANGE_IMPLEMENTATION_SELECTOR = hex"00000003";

    Implementation implementation;
    Implementation proxy;
    uint256 expectedTime;

    function setUp() public {
        implementation = new Implementation();
        proxy =
            Implementation(address(new ProxyBaseTimelockMinimal(address(implementation), address(this), "", TIMELOCK)));
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
            selector > 0x00000003 && selector != Implementation.toggle.selector
                && selector != Implementation.getFlag.selector
        );

        (bool s, bytes memory returnData) = address(proxy).call(bytes.concat(selector));
        assertFalse(s, "Bad call");
        assertEq(returnData.length, 0, "Wrong returnData length");
    }

    function test_getAndScheduleAdmin() public {
        ProxyBaseTimelockMinimal.ScheduledAdmin memory scheduledAdmin = _getScheduledAdmin();
        assertEq(scheduledAdmin.admin, address(0), "Wrong scheduled admin 1");
        assertEq(scheduledAdmin.time, type(uint256).max, "Wrong scheduled time 1");

        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        vm.expectEmit(true, false, false, true);
        emit ProxyBaseTimelockMinimal.NewAdminScheduled(vm.addr(1), expectedTime);
        bytes memory data = bytes.concat(SCHEDULE_ADMIN_SELECTOR, abi.encode(vm.addr(1)));
        (bool s, bytes memory returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewAdmin call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");

        scheduledAdmin = _getScheduledAdmin();
        assertEq(scheduledAdmin.admin, vm.addr(1), "Wrong scheduled admin 2");
        assertEq(scheduledAdmin.time, expectedTime, "Wrong scheduled time 2");

        vm.startPrank(vm.addr(1));
        data = bytes.concat(SCHEDULE_ADMIN_SELECTOR, abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad scheduleNewAdmin call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData"
        );
    }

    function test_getAndChangeAdmin() public {
        assertEq(_getAdmin(), address(this), "Wrong proxyAdmin 1");

        (bool s, bytes memory returnData) = address(proxy).call(CHANGE_ADMIN_SELECTOR);
        assertFalse(s, "Bad changeAdmin call 1");
        assertEq(
            returnData, abi.encodeWithSelector(ProxyBaseTimelockMinimal.NoAdminScheduled.selector), "Wrong returnData 1"
        );

        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        bytes memory data = bytes.concat(SCHEDULE_ADMIN_SELECTOR, abi.encode(vm.addr(1)));
        (s, returnData) = address(proxy).call(data);
        assertEq(_getAdmin(), address(this), "Wrong proxyAdmin 2");

        (s, returnData) = address(proxy).call(CHANGE_ADMIN_SELECTOR);
        assertFalse(s, "Bad changeAdmin call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.Timelocked.selector, expectedTime),
            "Wrong returnData 2"
        );

        vm.warp(expectedTime + 1);
        vm.startPrank(vm.addr(1));
        (s, returnData) = address(proxy).call(CHANGE_ADMIN_SELECTOR);
        assertFalse(s, "Bad changeAdmin call 3");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData 3"
        );
        vm.stopPrank();

        (s, returnData) = address(proxy).call(CHANGE_ADMIN_SELECTOR);
        assertTrue(s, "Bad changeAdmin call 4");
        assertEq(returnData.length, 0, "Wrong returnData length");

        ProxyBaseTimelockMinimal.ScheduledAdmin memory scheduledAdmin = _getScheduledAdmin();
        assertEq(scheduledAdmin.admin, address(0), "Wrong scheduled admin 1");
        assertEq(scheduledAdmin.time, type(uint256).max, "Wrong scheduled time 1");
        assertEq(_getAdmin(), vm.addr(1), "Wrong proxyAdmin 3");

        data = bytes.concat(SCHEDULE_ADMIN_SELECTOR, abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad scheduleNewAdmin call");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NotProxyAdmin.selector, address(this)),
            "Wrong returnData 4"
        );

        vm.startPrank(vm.addr(1));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        data = bytes.concat(SCHEDULE_ADMIN_SELECTOR, abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewAdmin call");
        assertEq(returnData.length, 0, "Wrong returnData length");

        scheduledAdmin = _getScheduledAdmin();
        assertEq(scheduledAdmin.admin, vm.addr(2), "Wrong scheduled admin 2");
        assertEq(scheduledAdmin.time, expectedTime, "Wrong scheduled time 2");
        vm.stopPrank();
    }

    function test_getAndScheduleNewImplementation() public {
        ProxyBaseTimelockMinimal.ScheduledImplementation memory scheduledImplementation = _getScheduledImplementation();
        assertEq(scheduledImplementation.implementation, address(0), "Wrong scheduled implementation 1");
        assertEq(scheduledImplementation.time, type(uint256).max, "Wrong scheduled time 1");
        assertEq(scheduledImplementation.data, "", "Wrong scheduled data 1");

        Implementation3 implementation3 = new Implementation3();
        bytes memory initData = abi.encodeCall(Implementation3.initialize, ("some data"));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        vm.expectEmit(true, false, false, true);
        emit ProxyBaseTimelockMinimal.NewImplementationScheduled(address(implementation3), initData, expectedTime);
        bytes memory data =
            bytes.concat(SCHEDULE_IMPLEMENTATION_SELECTOR, abi.encode(address(implementation3), initData));
        (bool s, bytes memory returnData) = address(proxy).call(data);
        assertTrue(s, "Bad scheduleNewImplementation call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");

        scheduledImplementation = _getScheduledImplementation();
        assertEq(scheduledImplementation.implementation, address(implementation3), "Wrong scheduled implementation 2");
        assertEq(scheduledImplementation.time, expectedTime, "Wrong scheduled time 2");
        assertEq(scheduledImplementation.data, initData, "Wrong scheduled data 2");

        vm.startPrank(vm.addr(1));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad getScheduledImplementation call 3");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData"
        );
    }

    function test_getAndChangeImplementation() public {
        assertEq(_getImplementation(), address(implementation), "Wrong implementation 1");

        (bool s, bytes memory returnData) = address(proxy).call(CHANGE_IMPLEMENTATION_SELECTOR);
        assertFalse(s, "Bad changeImplementation call 1");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NoImplementationScheduled.selector),
            "Wrong returnData 1"
        );

        Implementation3 implementation3 = new Implementation3();
        bytes memory initData = abi.encodeCall(Implementation3.initialize, ("some very long long long long long data"));
        expectedTime = vm.getBlockTimestamp() + TIMELOCK;
        bytes memory data =
            bytes.concat(SCHEDULE_IMPLEMENTATION_SELECTOR, abi.encode(address(implementation3), initData));
        (s, returnData) = address(proxy).call(data);
        assertEq(_getImplementation(), address(implementation), "Wrong implementation 2");

        (s, returnData) = address(proxy).call(CHANGE_IMPLEMENTATION_SELECTOR);
        assertFalse(s, "Bad changeImplementation call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.Timelocked.selector, expectedTime),
            "Wrong returnData 2"
        );

        vm.warp(expectedTime + 1);
        vm.startPrank(vm.addr(1));
        (s, returnData) = address(proxy).call(CHANGE_IMPLEMENTATION_SELECTOR);
        assertFalse(s, "Bad changeImplementation call 3");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseTimelockMinimal.NotProxyAdmin.selector, vm.addr(1)),
            "Wrong returnData 3"
        );
        vm.stopPrank();

        (s, returnData) = address(proxy).call(CHANGE_IMPLEMENTATION_SELECTOR);
        assertTrue(s, "Bad changeImplementation call 4");
        assertEq(returnData.length, 0, "Wrong returnData length");

        ProxyBaseTimelockMinimal.ScheduledImplementation memory scheduledImplementation = _getScheduledImplementation();
        assertEq(scheduledImplementation.implementation, address(0), "Wrong scheduled implementation");
        assertEq(scheduledImplementation.time, type(uint256).max, "Wrong scheduled time");
        assertEq(scheduledImplementation.data, "", "Wrong scheduled data");
        assertEq(_getImplementation(), address(implementation3), "Wrong implementation 3");
        assertEq(Implementation3(address(proxy)).getData(), "some very long long long long long data", "Wrong data");
    }

    function _getAdmin() internal view returns (address) {
        return abi.decode(bytes.concat(vm.load(address(proxy), ADMIN_SLOT)), (address));
    }

    function _getScheduledAdmin()
        internal
        view
        returns (ProxyBaseTimelockMinimal.ScheduledAdmin memory scheduledAdmin)
    {
        scheduledAdmin.admin = abi.decode(bytes.concat(vm.load(address(proxy), SCHEDULED_ADMIN_SLOT)), (address));
        scheduledAdmin.time =
            abi.decode(bytes.concat(vm.load(address(proxy), bytes32(uint256(SCHEDULED_ADMIN_SLOT) + 1))), (uint256));
    }

    function _getImplementation() internal view returns (address) {
        return abi.decode(bytes.concat(vm.load(address(proxy), IMPLEMENTATION_SLOT)), (address));
    }

    function _getScheduledImplementation()
        internal
        view
        returns (ProxyBaseTimelockMinimal.ScheduledImplementation memory scheduledImplementation)
    {
        scheduledImplementation.implementation =
            abi.decode(bytes.concat(vm.load(address(proxy), SCHEDULED_IMPLEMENTATION_SLOT)), (address));
        scheduledImplementation.time = abi.decode(
            bytes.concat(vm.load(address(proxy), bytes32(uint256(SCHEDULED_IMPLEMENTATION_SLOT) + 1))), (uint256)
        );

        bytes32 dataStorageOffset = bytes32(uint256(SCHEDULED_IMPLEMENTATION_SLOT) + 2);
        uint256 value = abi.decode(bytes.concat(vm.load(address(proxy), dataStorageOffset)), (uint256));

        if (value & 1 == 0) {
            // packed
            if (value == 0) {
                assembly ("memory-safe") {
                    mstore(add(scheduledImplementation, 0x40), 0x60)
                }
            } else {
                assembly ("memory-safe") {
                    let pointer := mload(0x40)
                    mstore(add(scheduledImplementation, 0x40), pointer)
                    let length := div(and(value, 0xff), 2)
                    mstore(pointer, length)
                    pointer := add(pointer, 0x20)
                    mstore(pointer, and(value, not(0xff)))
                    mstore(0x40, add(pointer, 0x20))
                }
            }
        } else {
            // not packed
            uint256 length = (value - 1) / 2;
            uint256 nSlots = length % 32 == 0 ? length / 32 : length / 32 + 1;
            bytes32[] memory values = new bytes32[](nSlots);
            dataStorageOffset = keccak256(abi.encode(dataStorageOffset));
            for (uint256 i; i < nSlots; ++i) {
                values[i] = vm.load(address(proxy), dataStorageOffset);
                assembly ("memory-safe") {
                    dataStorageOffset := add(dataStorageOffset, 1)
                }
            }
            assembly ("memory-safe") {
                let pointer := mload(0x40)
                mstore(add(scheduledImplementation, 0x40), pointer)
                mstore(pointer, length)
                pointer := add(pointer, 0x20)
                for { let i := 0 } lt(i, nSlots) { i := add(i, 1) } {
                    value := mload(add(values, mul(add(i, 1), 0x20)))
                    mstore(add(pointer, mul(i, 0x20)), value)
                }
                mstore(0x40, add(pointer, mul(nSlots, 0x20)))
            }
        }
    }
}
