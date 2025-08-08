//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC1967Proxy, ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ProxyBase
 * @notice A simple proxy contract.
 * @dev This proxy doesn't have any public functions.
 * @author https://github.com/nzmpi
 */
contract ProxyBase is ERC1967Proxy {
    error NotProxyAdmin(address);

    constructor(address implementation, address proxyAdmin, bytes memory initData)
        payable
        ERC1967Proxy(implementation, initData)
    {
        ERC1967Utils.changeAdmin(proxyAdmin);
    }

    receive() external payable {}

    /**
     * Proxy fallback function
     * @dev Selectors 0x00000000 - 0x00000004 are reserved for proxy functions.
     * @dev Selectors 0x00000001 and 0x00000002 can only be called by the proxy admin.
     * @dev 0x00000001: changeAdmin(address newAdmin) - where new admin is abi encoded.
     * @dev 0x00000002: upgradeToAndCall(address newImplementation, bytes data) -
     * where newImplementation and data are abi encoded.
     * @dev 0x00000003: getAdmin() - returns the proxy admin address.
     * @dev 0x00000004: getImplementation() - returns the implementation address.
     * @dev 0x00000000 can be called by the admin, but does nothing.
     * @dev All other selectors are forwarded to the implementation.
     * @dev Examples of calls can be found in test/ProxyBase.t.sol
     */
    fallback() external payable override {
        if (bytes4(msg.data[0:4]) < bytes4(hex"00000005")) {
            bytes4 selector = bytes4(msg.data[0:4]);
            if (selector < bytes4(hex"00000003")) {
                if (ERC1967Utils.getAdmin() != msg.sender) revert NotProxyAdmin(msg.sender);
                if (selector == bytes4(hex"00000001")) {
                    address newAdmin = abi.decode(msg.data[4:36], (address));
                    ERC1967Utils.changeAdmin(newAdmin);
                } else if (selector == bytes4(hex"00000002")) {
                    (address newImplementation, bytes memory data) =
                        abi.decode(msg.data[4:msg.data.length], (address, bytes));
                    ERC1967Utils.upgradeToAndCall(newImplementation, data);
                }
            } else {
                if (selector == bytes4(hex"00000003")) {
                    address admin = ERC1967Utils.getAdmin();
                    assembly ("memory-safe") {
                        mstore(0, admin)
                        return(12, 20)
                    }
                } else if (selector == bytes4(hex"00000004")) {
                    address implementation = ERC1967Utils.getImplementation();
                    assembly ("memory-safe") {
                        mstore(0, implementation)
                        return(12, 20)
                    }
                }
            }
        } else {
            _fallback();
        }
    }
}
