# Proxy Base

A Basic implementation of ERC1967 Proxy with no public functions.

The contract has 4 reserved selectors:
 - 0x00000000 - changes the admin of the proxy.
 - 0x00000001 - upgrades the proxy implementation with custom data call.
 - 0x00000002 - returns the proxy admin address.
 - 0x00000003 - returns the implementation address.

 First 2 selectors can be called only by the proxy admin. Examples of calls can be found [here](https://github.com/nzmpi/proxyBase/blob/main/test/ProxyBase.t.sol).

# Proxy Base with timelock

A Basic implementation of ERC1967 Proxy with timelock and no public functions.

The contract has 8 reserved selectors:
 - 0x00000000 - schedules the new admin address.
 - 0x00000001 - changes the admin of the proxy.
 - 0x00000002 - schedules the new implementation.
 - 0x00000003 - changes the implementation of the proxy.
 - 0x00000004 - returns the proxy admin address.
 - 0x00000005 - returns the NewAdmin struct.
 - 0x00000006 - returns the implementation address.
 - 0x00000007 - returns the NewImplementation struct.

 First 4 selectors can be called only by the proxy admin. Examples of calls can be found [here](https://github.com/nzmpi/proxyBase/blob/main/test/ProxyBaseTimelock.t.sol).

# Proxy Base Minimal

The same contract, but without `view` functions.

To get the admin/implementation address or scheduled structs read it directly from the storage,
e.g. https://docs.ethers.org/v6/api/providers/#Provider-getStorage