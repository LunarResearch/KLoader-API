# KLoader-API

In Windows 11  has been added a new registry branch: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\KLoader` (access to this registry key is possible only with system rights).

KLoader API consists of 7 functions:
* KLoaderReferenceModule
* KLoaderDereferenceModule
* KLoaderRegisterModule
* KLoaderQueryDispatchTable (not exported function)
* FindModuleByGuidLocked (internal function)
* CreateKModule (internal function)
* GetModuleServiceName (internal function)

KLoader API is located in the driver ndis.sys

<img align="left" src="https://raw.githubusercontent.com/LunarResearch/KLoader-API/main/ndis_kloader.png" width="755" height="575">
