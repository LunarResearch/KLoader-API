#ifndef _KLOADERAPI_H_
#define _KLOADERAPI_H_
#pragma once


#include <ntddk.h>
#include <cstdint>


DECLARE_HANDLE(KLOADER_MODULE_REFERENCE);
typedef KLOADER_MODULE_REFERENCE* PKLOADER_MODULE_REFERENCE;


/// <summary>
/// Enumerates
/// </summary>
enum ConfigKnobFlag {
    OnlyUpdateOnceAtBoot = 0,
    Uint32Datatype = 0,
    BooleanDatatype = 2,
    Uint64Datatype = 4,
    AllowDynamicUpdate = 32,
    MustBePowerOfTwo = 64
};


/// <summary>
/// Structures
/// </summary>
typedef struct _KLOADER_REFERENCE_MODULE_CONFIG {

}KLOADER_REFERENCE_MODULE_CONFIG, * PKLOADER_REFERENCE_MODULE_CONFIG;

typedef struct _KLOADER_MODULE_CHARACTERISTICS {

}KLOADER_MODULE_CHARACTERISTICS, * PKLOADER_MODULE_CHARACTERISTICS;


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderRegisterModule(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath,
    _In_opt_ PVOID arg3,
    _In_ PKLOADER_MODULE_CHARACTERISTICS pKModuleCharacts);


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderReferenceModule(
    _In_ PKLOADER_REFERENCE_MODULE_CONFIG pKModuleConfig,
    _Out_ PKLOADER_MODULE_REFERENCE* ppKModule);


_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FASTCALL
KLoaderDereferenceModule(
    _In_ PKLOADER_MODULE_REFERENCE pKModule);


NTSTATUS
FASTCALL
KLoaderQueryDispatchTable();


/// <summary>
/// Classes
/// </summary>
class KLoader
{
public:
    KLoader();

    NTSTATUS ReferenceModule(_In_ PKLOADER_REFERENCE_MODULE_CONFIG ModuleConfigRef, _Out_ PKLOADER_MODULE_REFERENCE* pKModuleRef)
    {
        KLockHolder m_lock;
        KModule* m_KModule;

        m_lock.m_State = *(uint32_t*)((int8_t*)ModuleConfigRef + 8);

        auto result = KLoader::ReferenceKModule((PGUID)&m_lock, &m_KModule);

        return result;
    };
    NTSTATUS ReferenceKModule(_In_ PGUID pGuid, _Out_ KModule** ppKModule)
    {
        int64_t m_KModule;
        NTSTATUS result;
        KModule* ModuleByGuidLocked;
        KLockHolder m_lock;
        
        m_lock.m_State = m_lock.Unlocked;
        m_lock.m_Lock = (PEX_PUSH_LOCK)this;
        m_lock.m_Region.m_Entered = false;
        m_lock.AcquireExclusive();

        ModuleByGuidLocked = KLoader::FindModuleByGuidLocked(pGuid);

        m_KModule = (int64_t)ModuleByGuidLocked;
        ++* (uint32_t*)(m_KModule + 16);
        
        m_lock.~KLockHolder();
        result = 0;
        *ppKModule = (KModule*)m_KModule;

        return result;
    };
    void DereferenceModule(_In_ PKLOADER_MODULE_REFERENCE)
    {

    };
    void DereferenceKModule(_In_ KModule*)
    {

    };
    NTSTATUS RegisterModule(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING, PVOID, _In_ PKLOADER_MODULE_CHARACTERISTICS)
    {

    };
    struct KModule* FindModuleByGuidLocked(_In_ PGUID)
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

        memset((void*)(Pool + 20), 0, NumberOfBytes);

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
    KModule();
    ~KModule(); // `scalar deleting destructor'

private:

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

#endif // _KLOADERAPI_H_
