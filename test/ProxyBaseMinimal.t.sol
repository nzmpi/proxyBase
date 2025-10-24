// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ProxyBaseMinimal} from "../src/ProxyBaseMinimal.sol";
import "./utils/Implementations.sol";
import {Test, console} from "forge-std/Test.sol";

contract ProxyBaseMinimalTest is Test {
    bytes32 constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes4 constant CHANGE_ADMIN_SELECTOR = 0;
    bytes4 constant CHANGE_IMPLEMENTATION_SELECTOR = 0x00000001;

    Implementation implementation;
    Implementation proxy;

    function setUp() public {
        implementation = new Implementation();
        proxy = Implementation(address(new ProxyBaseMinimal(address(implementation), address(this), "")));
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
            selector > 0x00000001 && selector != Implementation.toggle.selector
                && selector != Implementation.getFlag.selector
        );

        (bool s, bytes memory returnData) = address(proxy).call(bytes.concat(selector));
        assertFalse(s, "Bad call");
        assertEq(returnData.length, 0, "Wrong returnData length");
    }

    function test_getAndChangeProxyAdmin() public {
        assertEq(_getAdmin(), address(this), "Wrong old proxy admin");

        bytes memory data = bytes.concat(CHANGE_ADMIN_SELECTOR, abi.encode(vm.addr(1)));
        (bool s, bytes memory returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeAdmin call 1");
        assertEq(returnData.length, 0, "Wrong returnData length");
        assertEq(_getAdmin(), vm.addr(1), "Wrong new proxy admin 1");

        data = bytes.concat(CHANGE_ADMIN_SELECTOR, abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertFalse(s, "Bad changeAdmin call 2");
        assertEq(
            returnData,
            abi.encodeWithSelector(ProxyBaseMinimal.NotProxyAdmin.selector, address(this)),
            "Wrong returnData"
        );

        vm.prank(vm.addr(1));
        data = bytes.concat(CHANGE_ADMIN_SELECTOR, abi.encode(vm.addr(2)));
        (s, returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeAdmin call 3");
        assertEq(returnData.length, 0, "Wrong returnData length");
        assertEq(_getAdmin(), vm.addr(2), "Wrong new proxy admin 2");
    }

    function test_getAndChangeImplementation() public {
        assertEq(_getImplementation(), address(implementation), "Wrong old implementation");

        vm.expectRevert();
        Implementation2(address(proxy)).getReverseFlag();

        address newImplementation = address(new Implementation2());
        bytes memory data = bytes.concat(
            CHANGE_IMPLEMENTATION_SELECTOR,
            abi.encode(newImplementation, abi.encodeCall(Implementation2.initialize, true))
        );
        (bool s, bytes memory returnData) = address(proxy).call(data);
        assertTrue(s, "Bad changeImplementation call");
        assertEq(returnData.length, 0, "Wrong returnData length");
        assertEq(_getImplementation(), newImplementation, "Wrong new implementation");
        assertFalse(Implementation2(address(proxy)).getReverseFlag(), "Wrong reverse flag");
    }

    function _getAdmin() internal view returns (address) {
        return abi.decode(bytes.concat(vm.load(address(proxy), ADMIN_SLOT)), (address));
    }

    function _getImplementation() internal view returns (address) {
        return abi.decode(bytes.concat(vm.load(address(proxy), IMPLEMENTATION_SLOT)), (address));
    }
}
