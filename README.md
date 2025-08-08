# Proxy Base

A Basic implementation of ERC1967 Proxy with no public functions.

The contract has 5 reserved selectors:
 - 0x00000001 - changes the admin of the proxy.
 - 0x00000002 - upgrades the proxy implementation with custom data call.
 - 0x00000003 - returns the proxy admin address.
 - 0x00000004 - returns the implementation address.
 - 0x00000000 - can be called by the admin, but does nothing.

 First 2 selectors can be called only by the proxy admin. Examples of calls can be found [here](https://github.com/nzmpi/proxyBase/blob/main/test/ProxyBase.t.sol).