#ifndef _KLOADERAPI_H_
#define _KLOADERAPI_H_
#pragma once


#include <ntddk.h> // Windows Driver Kit (WDK)
#include <stdint.h>


DECLARE_HANDLE(KLOADER_MODULE_REFERENCE);
typedef KLOADER_MODULE_REFERENCE* PKLOADER_MODULE_REFERENCE;


struct DECLSPEC_ALIGN(16) uint128_t {
    uint64_t Low;
    int64_t High;
};


#define __CASSERT_N0__(l) COMPILE_TIME_ASSERT_ ## l
#define __CASSERT_N1__(l) __CASSERT_N0__(l)
#define CASSERT(cnd) typedef char __CASSERT_N1__(__LINE__) [(cnd) ? 1 : -1]

template<typename T> bool is_mul_ok(T count, T elsize)
{
    CASSERT((T)(-1) > 0);
    if (elsize == 0 || count == 0)
        return true;
    return count <= ((T)(-1)) / elsize;
}


enum ConfigKnobFlag {
    OnlyUpdateOnceAtBoot = 0,
    Uint32Datatype = 0,
    BooleanDatatype = 2,
    Uint64Datatype = 4,
    AllowDynamicUpdate = 32,
    MustBePowerOfTwo = 64
};


typedef struct _KLOADER_REFERENCE_MODULE_CONFIG {

} KLOADER_REFERENCE_MODULE_CONFIG, * PKLOADER_REFERENCE_MODULE_CONFIG;

typedef struct _KLOADER_MODULE_CHARACTERISTICS {

} KLOADER_MODULE_CHARACTERISTICS, * PKLOADER_MODULE_CHARACTERISTICS;


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderReferenceModule(
    _In_ PKLOADER_REFERENCE_MODULE_CONFIG pKModuleConfigRef,
    _Out_ PKLOADER_MODULE_REFERENCE pKModuleRef);


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderDereferenceModule(
    _In_ KLOADER_MODULE_REFERENCE KModuleRef);


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderRegisterModule(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath,
    _In_opt_ PVOID arg3,
    _In_ PKLOADER_MODULE_CHARACTERISTICS pKModuleCharacts);


NTSTATUS
FASTCALL
KLoaderQueryDispatchTable(
    // EXECUTION_CONTEXT_DISPATCH_TABLE_ID  2595FE53-954B-AF47-8B1F-F278B7D588FD
);


class KLoader
{
public:
    KLoader()
    {
        *(uint64_t*)this = 0;
        *((uint64_t*)this + 2) = *((int8_t*)this + 8);
        *((uint64_t*)this + 1) = *((int8_t*)this + 8);
    };
    NTSTATUS ReferenceModule(_In_ PKLOADER_REFERENCE_MODULE_CONFIG pKModuleConfigRef, _Out_ PKLOADER_MODULE_REFERENCE pKModuleRef)
    {
        KLockHolder m_lock;
        KModule* m_KModule;

        m_lock.m_State = *(uint32_t*)((int8_t*)pKModuleConfigRef + 8);

        auto result = KLoader::ReferenceKModule((PGUID)&m_lock, &m_KModule);

        if (!result)
        {
            DriverService m_DriverService;
            
            auto result = m_DriverService.Reference();
            
            if (!result)
            {
                ExAllocatePoolWithTag(PagedPool, 0x20, 0x62694C4E);
            }
        }

        return result;
    };
    NTSTATUS ReferenceKModule(_In_ PGUID pGuid, _Out_ KModule** ppKModule)
    {
        KLockHolder m_lock;
        int64_t m_KModule;
        KModule* ModuleByGuidLocked;

        m_lock.m_State = m_lock.Unlocked;
        m_lock.m_Lock = (PEX_PUSH_LOCK)this;
        m_lock.m_Region.m_Entered = false;
        m_lock.AcquireExclusive();

        ModuleByGuidLocked = KLoader::FindModuleByGuidLocked(pGuid);

        m_KModule = (int64_t)ModuleByGuidLocked;
        ++* (uint32_t*)(m_KModule + 16);

        m_lock.~KLockHolder();
        NTSTATUS result = 0;
        *ppKModule = (KModule*)m_KModule;

        return result;
    };
    KModule* FindModuleByGuidLocked(_In_ PGUID pGuid)
    {

    };
    void DereferenceModule(_In_ KLOADER_MODULE_REFERENCE KModuleRef)
    {

    };
    void DereferenceKModule(_In_ KModule* pKModule)
    {

    };
    NTSTATUS RegisterModule(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING, PVOID, _In_ PKLOADER_MODULE_CHARACTERISTICS)
    {

    };
};

class KLockHolder
{
public:
    enum {
        Unlocked = 0,
        Shared = 1,
        Exclusive = 2
    };
    struct {
        uint32_t m_State;
        PEX_PUSH_LOCK m_Lock;
        struct {
            bool m_Entered;
        } m_Region;
    };

    void AcquireExclusive()
    {
        PEX_PUSH_LOCK m_Lock{};
        KeEnterCriticalRegion();
        m_Lock = this->m_Lock;
        this->m_Region.m_Entered = true;
        ExAcquirePushLockExclusive(m_Lock);
        this->m_State = Exclusive;
    };
    void AcquireShared()
    {
        PEX_PUSH_LOCK m_Lock{};
        KeEnterCriticalRegion();
        m_Lock = this->m_Lock;
        this->m_Region.m_Entered = true;
        ExAcquirePushLockShared(m_Lock);
        this->m_State = Shared;
    };
    void ReleaseExclusive()
    {
        ExReleasePushLockExclusive(this->m_Lock);
        this->m_State = Unlocked;
        this->m_Region.m_Entered = false;
        KeLeaveCriticalRegion();
    };
    void ReleaseShared()
    {
        ExReleasePushLockShared(this->m_Lock);
        this->m_State = Unlocked;
        this->m_Region.m_Entered = false;
        KeLeaveCriticalRegion();
    };

    ~KLockHolder()
    {
        auto State = this->m_State - 1;
        if (State) {
            if (State == Shared) {
                ExReleasePushLockExclusive(this->m_Lock);
                this->m_State = Unlocked;
                this->m_Region.m_Entered = false;
                KeLeaveCriticalRegion();
            }
        }
        else KLockHolder::ReleaseShared();

        if (this->m_Region.m_Entered) {
            this->m_Region.m_Entered = false;
            KeLeaveCriticalRegion();
        }
    };
};

class KPushLockManualConstruct
{
public:
    void Initialize()
    {
        *(uint64_t*)this = 0;
    };
};

class KHistogram
{
public:
    KHistogram* Create(uint64_t a1, uint64_t count, uint32_t elsize)
    {
        if (elsize < 2) return 0;
        if (!is_mul_ok(count, (uint64_t)elsize)) return 0;
        if (a1 + count * elsize < a1) return 0;

        auto NumberOfBytes = static_cast<size_t>(elsize) * 2;
        if (NumberOfBytes > UINT32_MAX) return 0;
        if ((uint32_t)NumberOfBytes >= (UINT32_MAX - 19)) return 0;

        auto Pool = (int64_t)ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes + 20, 0x7473484B);

        int64_t result = Pool;
        if (!Pool) return 0;

        *(uint64_t*)Pool = a1;
        *(uint64_t*)(Pool + 8) = count;
        *(uint32_t*)(Pool + 16) = elsize;

        memset((PVOID)(Pool + 20), 0, NumberOfBytes);

        return (KHistogram*)result;
    };
    void IncrementBucket(int64_t Addend)
    {
        if ((uint16_t)InterlockedIncrement16((int16_t*)this + Addend + 10) > 0xFF00)
            InterlockedDecrement16((int16_t*)this + Addend + 10);
    };
};

class KModule
{
public:
    LONGLONG kModule(int64_t a1, int64_t* a2, int64_t* a3)
    {
        *(uint128_t*)a1 = *(uint128_t*)0;
        *(uint32_t*)(a1 + 16) = 0;
        *(uint128_t*)(a1 + 20) = *(uint128_t*)*a2;

        int64_t v3 = *a3;
        *a3 = 0;

        *(uint64_t*)(a1 + 40) = v3;
        *(uint64_t*)(a1 + 48) = 0;
        *(uint32_t*)(a1 + 56) = 0;
        *(uint64_t*)(a1 + 64) = 0;
        *(uint64_t*)(a1 + 72) = 0;
        *(uint64_t*)(a1 + 80) = 0;
        *(uint64_t*)(a1 + 88) = 0;
        *(uint64_t*)(a1 + 96) = 0;
        *(uint64_t*)(a1 + 104) = a1 + 104;
        *(uint64_t*)(a1 + 112) = a1 + 104;

        return a1;
    };
    PVOID ScalarDeletingDestructor(PVOID P, uint32_t a2) // ~KModule
    {
        DriverService m_DriverService;
        
        m_DriverService.~DriverService();
        if ((a2 & 1) != 0 && P)
            ExFreePoolWithTag(P, 0x62694C4E);
        return P;
    };
};

class KAcquireSpinLock
{
public:
    ~KAcquireSpinLock()
    {
        if (this->m_oldIrql != 0xFF) {
            KeReleaseSpinLock(&this->m_lock, this->m_oldIrql);
            this->m_oldIrql = -1;
        }
    };

private:
    struct {
        KIRQL m_oldIrql;
        KSPIN_LOCK m_lock;
    };
};

class DriverService
{
public:
    NTSTATUS Reference()
    {

    };
    NTSTATUS Dereference()
    {

    };
    NTSTATUS Open(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath)
    {

    };
    void Close()
    {
        ZwUnloadDriver(*(PUNICODE_STRING*)this);
        *((uint64_t*)this + 3) = 0;
    };

    ~DriverService()
    {
        PVOID P = *(PVOID*)this;
        *(uint64_t*)this = 0;
        if (P) ExFreePoolWithTag(P, 0);
    };
};

#endif // _KLOADERAPI_H_
