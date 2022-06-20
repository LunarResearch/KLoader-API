# KLoader-API

In Windows 11  has been added a new registry branch: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\KLoader` (access to this registry key is possible only with system rights).

KLoader is a new kernel API located in the driver ndis.sys

This kernel API consists of 4 functions:
* KLoaderReferenceModule
* KLoaderDereferenceModule
* KLoaderRegisterModule
* KLoaderQueryDispatchTable
