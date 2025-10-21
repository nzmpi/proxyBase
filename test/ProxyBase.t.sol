// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ProxyBase} from "../src/ProxyBase.sol";
import "./utils/Implementations.sol";
import {Test, console} from "forge-std/Test.sol";

contract ProxyBaseTest is Test {
    Implementation implementation;
    Implementation proxy;

    function setUp() public {
        implementation = new Implementation();
        proxy = Implementation(address(new ProxyBase(address(implementation), address(this), "")));
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

    function test_getAndChangeProxyAdmin() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000002");
        assertTrue(s, "Bad getAdmin call 1");
        address admin = abi.decode(returnData, (address));
        assertEq(admin, address(this), "Wrong old proxy admin");

        bytes memory data = bytes.concat(hex"00000000", abi.encode(vm.addr(1)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeAdmin call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000002");
        assertTrue(s, "Bad getAdmin call 2");
        admin = abi.decode(returnData, (address));
        assertEq(admin, vm.addr(1), "Wrong new proxy admin 1");

        data = bytes.concat(hex"00000000", abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeAdmin call 2");
        assertEq(
            returnData, abi.encodeWithSelector(ProxyBase.NotProxyAdmin.selector, address(this)), "Wrong returnData"
        );

        vm.prank(vm.addr(1));
        data = bytes.concat(hex"00000000", abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeAdmin call 3");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000002");
        assertTrue(s, "Bad getAdmin call 3");
        admin = abi.decode(returnData, (address));
        assertEq(admin, vm.addr(2), "Wrong new proxy admin 2");
    }

    function test_getAndChangeImplementation() public {
        (bool s, bytes memory returnData) = address(proxy).call(hex"00000003");
        assertTrue(s, "Bad getImplementation call 1");
        address impl = abi.decode(returnData, (address));
        assertEq(impl, address(implementation), "Wrong old implementation");

        vm.expectRevert();
        Implementation2(address(proxy)).getReverseFlag();

        address newImplementation = address(new Implementation2());
        bytes memory data =
            bytes.concat(hex"00000001", abi.encode(newImplementation, abi.encodeCall(Implementation2.initialize, true)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeImplementation call");
        assertEq(returnData.length, 0, "Wrong returnData length");

        (s, returnData) = address(proxy).call(hex"00000003");
        assertTrue(s, "Bad getImplementation call 2");
        impl = abi.decode(returnData, (address));
        assertEq(impl, newImplementation, "Wrong new implementation");

        assertFalse(Implementation2(address(proxy)).getReverseFlag(), "Wrong reverse flag");
    }
}
