//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC1967Proxy, ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ProxyBaseMinimal
 * @notice A simple minimal proxy contract.
 * @dev This proxy doesn't have any public functions.
 * @author https://github.com/nzmpi
 */
contract ProxyBaseMinimal is ERC1967Proxy {
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
     * @dev Selectors 0x00000000 - 0x00000001 are reserved for proxy functions
     * and can only be called by the proxy admin.
     * @dev 0x00000000: changeAdmin(address newAdmin) - where new admin is abi encoded.
     * @dev 0x00000001: changeImplementation(address newImplementation, bytes data) -
     * where newImplementation and data are abi encoded.
     * @dev All other selectors are forwarded to the implementation.
     * @dev To get the admin or implementation address read it directly from the storage,
     * e.g. https://docs.ethers.org/v6/api/providers/#Provider-getStorage
     * @dev Examples of calls can be found in test/ProxyBaseMinimal.t.sol
     */
    fallback() external payable override {
        if (bytes4(msg.data[0:4]) < 0x00000002) {
            if (ERC1967Utils.getAdmin() != msg.sender) revert NotProxyAdmin(msg.sender);
            if (bytes4(msg.data[0:4]) == 0) {
                _changeAdmin();
            } else {
                _changeImplementation();
            }
        } else {
            _fallback();
        }
    }

    /**
     * Change the proxy admin
     */
    function _changeAdmin() internal {
        address newAdmin = abi.decode(msg.data[4:36], (address));
        ERC1967Utils.changeAdmin(newAdmin);
    }

    /**
     * Change the implementation
     */
    function _changeImplementation() internal {
        (address newImplementation, bytes memory data) = abi.decode(msg.data[4:], (address, bytes));
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }
}
