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
    // EIP-7201: keccak256(abi.encode(uint256(keccak256("proxyBaseTimelock.storage.scheduledAdmin")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SCHEDULED_ADMIN_SLOT = 0xf4368cc27f089e2864e7549f41cfcd089cf3dac6a4a45da1e986635a00a9e100;
    // EIP-7201: keccak256(abi.encode(uint256(keccak256("proxyBaseTimelock.storage.scheduledImplementation")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SCHEDULED_IMPLEMENTATION_SLOT =
        0x65eefe6fc6d4243074c6129566699e1b26d56abc09f340bdbc9ceb10e6169b00;

    uint256 private immutable TIME_LOCK;

    error NoAdminScheduled();
    error NoImplementationScheduled();
    error NotProxyAdmin(address);
    error Timelocked(uint256);

    event NewAdminScheduled(address indexed admin, uint256 time);
    event NewImplementationScheduled(address indexed implementation, bytes data, uint256 time);

    struct ScheduledAdmin {
        address admin;
        uint256 time;
    }

    struct ScheduledImplementation {
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
        ScheduledAdmin storage scheduledAdmin = _getScheduledAdminStruct();
        scheduledAdmin.time = type(uint256).max;
        ScheduledImplementation storage scheduledImplementation = _getScheduledImplementationStruct();
        scheduledImplementation.time = type(uint256).max;
    }

    receive() external payable {}

    /**
     * Proxy fallback function
     * @dev Selectors 0x00000000 - 0x00000007 are reserved for proxy functions.
     * @dev Selectors 0x00000000-0x00000003 can only be called by the proxy admin.
     * @dev 0x00000000: scheduleAdmin(address newAdmin) - where new admin is abi encoded.
     * @dev 0x00000001: changeAdmin() - updates the admin to the scheduled one.
     * @dev 0x00000002: scheduleImplementation(address newImplementation, bytes data) -
     * where newImplementation and data are abi encoded.
     * @dev 0x00000003: changeImplementation() - updates the implementation to the scheduled one.
     * @dev 0x00000004: getAdmin() - returns the proxy admin address.
     * @dev 0x00000005: getScheduledAdmin() - returns the ScheduledAdmin struct.
     * @dev 0x00000006: getImplementation() - returns the implementation address.
     * @dev 0x00000007: getScheduledImplementation() - returns the ScheduledImplementation struct.
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
                        _scheduleAdmin();
                    } else {
                        _changeAdmin();
                    }
                } else {
                    if (selector == 0x00000002) {
                        _scheduleImplementation();
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
    function _scheduleAdmin() internal {
        address admin = abi.decode(msg.data[4:36], (address));
        ScheduledAdmin storage scheduledAdmin = _getScheduledAdminStruct();
        scheduledAdmin.admin = admin;
        uint256 time = block.timestamp + TIME_LOCK;
        scheduledAdmin.time = time;

        emit NewAdminScheduled(admin, time);
    }

    /**
     * Change the admin
     * @dev Reverts if no admin is scheduled or timelocked
     */
    function _changeAdmin() internal {
        ScheduledAdmin storage scheduledAdmin = _getScheduledAdminStruct();
        address admin = scheduledAdmin.admin;
        if (admin == address(0)) revert NoAdminScheduled();
        if (scheduledAdmin.time > block.timestamp) revert Timelocked(scheduledAdmin.time);

        scheduledAdmin.admin = address(0);
        scheduledAdmin.time = type(uint256).max;

        ERC1967Utils.changeAdmin(admin);
    }

    /**
     * Schedule a new implementation
     */
    function _scheduleImplementation() internal {
        (address implementation, bytes memory data) = abi.decode(msg.data[4:msg.data.length], (address, bytes));
        ScheduledImplementation storage scheduledImplementation = _getScheduledImplementationStruct();
        scheduledImplementation.implementation = implementation;
        scheduledImplementation.data = data;
        uint256 time = block.timestamp + TIME_LOCK;
        scheduledImplementation.time = time;

        emit NewImplementationScheduled(implementation, data, time);
    }

    /**
     * Change the implementation
     * @dev Reverts if no implementation is scheduled or timelocked
     */
    function _changeImplementation() internal {
        ScheduledImplementation storage scheduledImplementation = _getScheduledImplementationStruct();
        address implementation = scheduledImplementation.implementation;
        if (implementation == address(0)) revert NoImplementationScheduled();
        if (scheduledImplementation.time > block.timestamp) revert Timelocked(scheduledImplementation.time);

        bytes memory data = scheduledImplementation.data;
        scheduledImplementation.implementation = address(0);
        scheduledImplementation.data = "";
        scheduledImplementation.time = type(uint256).max;

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
     * Get the ScheduledAdmin struct
     */
    function _getScheduledAdmin() internal view {
        assembly ("memory-safe") {
            let admin := sload(SCHEDULED_ADMIN_SLOT)
            let time := sload(add(SCHEDULED_ADMIN_SLOT, 1))
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
     * Get the ScheduledImplementation struct
     */
    function _getScheduledImplementation() internal pure {
        ScheduledImplementation memory scheduledImplementation = _getScheduledImplementationStruct();
        assembly ("memory-safe") {
            // 0xa0 = 5 * 32: struct offset, address slot, time slot, data offset, data length
            let length := add(0xa0, mload(add(scheduledImplementation, 0x60)))
            let remainder := mod(length, 32)
            if gt(remainder, 0) { length := add(length, sub(32, remainder)) }
            // add struct offset
            let structOffset := sub(scheduledImplementation, 0x20)
            mstore(structOffset, 0x20)
            // update scheduledImplementation.data offset
            mstore(add(scheduledImplementation, 0x40), 0x60)
            return(structOffset, length)
        }
    }

    /**
     * Get the ScheduledAdmin struct storage
     */
    function _getScheduledAdminStruct() internal pure returns (ScheduledAdmin storage scheduledAdmin) {
        assembly ("memory-safe") {
            scheduledAdmin.slot := SCHEDULED_ADMIN_SLOT
        }
    }

    /**
     * Get the ScheduledImplementation struct storage
     */
    function _getScheduledImplementationStruct()
        internal
        pure
        returns (ScheduledImplementation storage scheduledImplementation)
    {
        assembly ("memory-safe") {
            scheduledImplementation.slot := SCHEDULED_IMPLEMENTATION_SLOT
        }
    }
}
