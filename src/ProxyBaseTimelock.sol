//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC1967Proxy, ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ProxyBaseTimelock
 * @notice A simple proxy contract with a timelock.
 * @dev This proxy doesn't have any public functions.
 * @author https://github.com/nzmpi
 */
contract ProxyBaseTimelock is ERC1967Proxy {
    // EIP-7201: keccak256(abi.encode(uint256(keccak256("proxyBaseTimelock.storage.newAdmin")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant NEW_ADMIN_STORAGE_SLOT = 0x9b3b3a8fa04a8fb66068a87804c3359f5507efd49b15c25f4d531a0b7dfe4f00;
    // EIP-7201: keccak256(abi.encode(uint256(keccak256("proxyBaseTimelock.storage.newImplementation")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant NEW_IMPLEMENTATION_STORAGE_SLOT =
        0xcd2c3aaaee26f2e538febaa4bbf353e4f1b969e58d1364be733ae3916a767e00;

    uint256 private immutable TIME_LOCK;

    error NoAdminScheduled();
    error NoImplementationScheduled();
    error NotProxyAdmin(address);
    error Timelocked(uint256);

    event NewAdminScheduled(address indexed admin, uint256 time);
    event NewImplementationScheduled(address indexed implementation, bytes data, uint256 time);

    struct NewAdmin {
        address admin;
        uint256 time;
    }

    struct NewImplementation {
        address implementation;
        uint256 time;
        bytes data;
    }

    constructor(address implementation, address proxyAdmin, bytes memory initData, uint256 timelock)
        payable
        ERC1967Proxy(implementation, initData)
    {
        ERC1967Utils.changeAdmin(proxyAdmin);
        TIME_LOCK = timelock;
        NewAdmin storage newAdmin = _getNewAdminStruct();
        newAdmin.time = type(uint256).max;
        NewImplementation storage newImplementation = _getNewImplementationStruct();
        newImplementation.time = type(uint256).max;
    }

    receive() external payable {}

    /**
     * Proxy fallback function
     * @dev Selectors 0x00000000 - 0x00000007 are reserved for proxy functions.
     * @dev Selectors 0x00000000-0x00000003 can only be called by the proxy admin.
     * @dev 0x00000000: scheduleNewAdmin(address newAdmin) - where new admin is abi encoded.
     * @dev 0x00000001: changeAdmin() - updates the admin to the scheduled one.
     * @dev 0x00000002: scheduleNewImplementation(address newImplementation, bytes data) -
     * where newImplementation and data are abi encoded.
     * @dev 0x00000003: changeImplementation() - updates the implementation to the scheduled one.
     * @dev 0x00000004: getAdmin() - returns the proxy admin address.
     * @dev 0x00000005: getScheduledAdmin() - returns the NewAdmin struct.
     * @dev 0x00000006: getImplementation() - returns the implementation address.
     * @dev 0x00000007: getScheduledImplementation() - returns the NewImplementation struct.
     * @dev All other selectors are forwarded to the implementation.
     * @dev Examples of calls can be found in test/ProxyBaseTimeLock.t.sol
     */
    fallback() external payable override {
        if (bytes4(msg.data[0:4]) < 0x00000008) {
            bytes4 selector = bytes4(msg.data[0:4]);
            if (selector < 0x00000004) {
                if (ERC1967Utils.getAdmin() != msg.sender) revert NotProxyAdmin(msg.sender);
                if (selector < 0x00000002) {
                    if (selector == 0) {
                        _scheduleNewAdmin();
                    } else {
                        _changeAdmin();
                    }
                } else {
                    if (selector == 0x00000002) {
                        _scheduleNewImplementation();
                    } else {
                        _changeImplementation();
                    }
                }
            } else {
                if (selector < 0x00000006) {
                    if (selector == 0x00000004) {
                        _getAdmin();
                    } else {
                        _getScheduledAdmin();
                    }
                } else {
                    if (selector == 0x00000006) {
                        _getImplementation();
                    } else {
                        _getScheduledImplementation();
                    }
                }
            }
        } else {
            _fallback();
        }
    }

    /**
     * Schedule a new admin of the proxy
     */
    function _scheduleNewAdmin() internal {
        address admin = abi.decode(msg.data[4:36], (address));
        NewAdmin storage newAdmin = _getNewAdminStruct();
        newAdmin.admin = admin;
        uint256 time = block.timestamp + TIME_LOCK;
        newAdmin.time = time;

        emit NewAdminScheduled(admin, time);
    }

    /**
     * Change the admin
     * @dev Reverts if no admin is scheduled or timelocked
     */
    function _changeAdmin() internal {
        NewAdmin storage newAdmin = _getNewAdminStruct();
        address admin = newAdmin.admin;
        if (admin == address(0)) revert NoAdminScheduled();
        if (newAdmin.time > block.timestamp) revert Timelocked(newAdmin.time);

        newAdmin.admin = address(0);
        newAdmin.time = type(uint256).max;

        ERC1967Utils.changeAdmin(admin);
    }

    /**
     * Schedule a new implementation
     */
    function _scheduleNewImplementation() internal {
        (address implementation, bytes memory data) = abi.decode(msg.data[4:msg.data.length], (address, bytes));
        NewImplementation storage newImplementation = _getNewImplementationStruct();
        newImplementation.implementation = implementation;
        newImplementation.data = data;
        uint256 time = block.timestamp + TIME_LOCK;
        newImplementation.time = time;

        emit NewImplementationScheduled(implementation, data, time);
    }

    /**
     * Change the implementation
     * @dev Reverts if no implementation is scheduled or timelocked
     */
    function _changeImplementation() internal {
        NewImplementation storage newImplementation = _getNewImplementationStruct();
        address implementation = newImplementation.implementation;
        if (implementation == address(0)) revert NoImplementationScheduled();
        if (newImplementation.time > block.timestamp) revert Timelocked(newImplementation.time);

        bytes memory data = newImplementation.data;
        newImplementation.implementation = address(0);
        newImplementation.data = "";
        newImplementation.time = type(uint256).max;

        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    /**
     * Get the admin address
     */
    function _getAdmin() internal view {
        address admin = ERC1967Utils.getAdmin();
        assembly ("memory-safe") {
            mstore(0, admin)
            return(0, 32)
        }
    }

    /**
     * Get the NewAdmin struct
     */
    function _getScheduledAdmin() internal view {
        assembly ("memory-safe") {
            let admin := sload(NEW_ADMIN_STORAGE_SLOT)
            let time := sload(add(NEW_ADMIN_STORAGE_SLOT, 1))
            mstore(0x20, time)
            mstore(0, admin)
            return(0, 64)
        }
    }

    /**
     * Get the implementation address
     */
    function _getImplementation() internal view {
        address implementation = ERC1967Utils.getImplementation();
        assembly ("memory-safe") {
            mstore(0, implementation)
            return(0, 32)
        }
    }

    /**
     * Get the NewImplementation struct
     */
    function _getScheduledImplementation() internal pure {
        NewImplementation memory newImplementation = _getNewImplementationStruct();
        assembly ("memory-safe") {
            // 0xa0 = 5 * 32: struct offset, address slot, time slot, data offset, data length
            let length := add(0xa0, mload(add(newImplementation, 0x60)))
            let remainder := mod(length, 32)
            if gt(remainder, 0) { length := add(length, sub(32, remainder)) }
            // add struct offset
            let structOffset := sub(newImplementation, 0x20)
            mstore(structOffset, 0x20)
            // update newImplementation.data offset
            mstore(add(newImplementation, 0x40), 0x60)
            return(structOffset, length)
        }
    }

    /**
     * Get the NewAdmin struct storage
     */
    function _getNewAdminStruct() internal pure returns (NewAdmin storage newAdmin) {
        assembly ("memory-safe") {
            newAdmin.slot := NEW_ADMIN_STORAGE_SLOT
        }
    }

    /**
     * Get the NewImplementation struct storage
     */
    function _getNewImplementationStruct() internal pure returns (NewImplementation storage newImplementation) {
        assembly ("memory-safe") {
            newImplementation.slot := NEW_IMPLEMENTATION_STORAGE_SLOT
        }
    }
}
