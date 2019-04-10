/*
 *  Copyright (C)
 *
 *  Written by Davit Kalantaryan <davit.kalantaryan@desy.de>
 */

 /**
  * @file       crash_investigator.c
  * @copyright
  * @brief      Source file implements APIs for investigating crashes
  * @author     Davit Kalantaryan <davit.kalantaryan@desy.de>
  * @date       2019 Mar 30
  * @details
  *  Details :  @n
  *   - https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/crtsetallochook?view=vs-2017 
  *   - https://ide.geeksforgeeks.org/F10DpiEh8N 
  */


#define USE_MEMORY_HOOKS


#ifdef __GNUC__
//#pragma GCC diagnostic ignored "-Wreserved-id-macro"
//#define DISABLE_UNUSED_PARS _Pargma()
#endif

#ifndef	_GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include "crash_investigator.h"
#include <unistd.h>
#ifndef _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>

#include <execinfo.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <memory.h>
#include <signal.h>

#define STACK_MAX_SIZE  256
#define BACKTRACE_MALLOC_HOOK_BUFFER_SIZE   16384

#define MEMOR_TYPE_REGULAR 0
#define MEMOR_TYPE_MMAP 1
#define MEMOR_TYPE_POOL 2

#define MEMORY_SIGNATURE    20132015


#define   THREAD_LOCAL


BEGIN_C_DECL_2

#define FROM_BUFF_TO_HEADER(_buffer) REINTERPRET_CAST(struct SMemoryHeader*,(_buffer))
#define FROM_USER_BUFF_TO_HEADER(_buffer) REINTERPRET_CAST(struct SMemoryHeader*,STATIC_CAST(char*,_buffer)-sizeof(struct SMemoryHeader))

typedef void* (*TypeMallocLib)(size_t);
typedef void (*TypeFreeLib)(void*);
typedef void* (*TypeMalloc2)(enum HookType,size_t);
typedef void* (*TypeRealloc)(void*,size_t);
typedef void* (*TypeCalloc)(size_t nmemb, size_t size);
typedef void (*TypeFree2)(enum HookType,void*);


/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/


#ifdef USE_MEMORY_HOOKS
#define IS_STATIC   static
typedef void* (*TypeMallocHook)(size_t, const void *);
typedef void* (*TypeReallocHook)(void*,size_t, const void *);
typedef void  (*TypeFreeHook)(void *, const void*);
extern TypeMallocHook __malloc_hook;
extern TypeReallocHook __realloc_hook;
extern TypeFreeHook __free_hook;
static TypeMallocHook s_malloc_hook_initial = NEWNULLPTR;
static TypeReallocHook s_realloc_hook_initial= NEWNULLPTR;
static TypeFreeHook s_free_hook_initial= NEWNULLPTR;
IS_STATIC void* hooked_malloc(size_t a_size, const void* a_nextMem);
IS_STATIC void* hooked_realloc(void *a_ptr, size_t a_size,const void* a_nextMem);
IS_STATIC void hooked_free(void *a_ptr, const void* a_nextMem);
static int s_nLibraryInited = 0;
#else
#define IS_STATIC
#define hooked_malloc(_sizeTypeAndVar, _nextMem)  malloc(_sizeTypeAndVar)
#define hooked_realloc(_ptrTypeAndVar, _sizeTypeAndVar, _nextMem) realloc(_ptrTypeAndVar, _sizeTypeAndVar)
#define hooked_free(_ptrTypeAndVar, _nextMem) free(_ptrTypeAndVar)
static TypeMallocLib s_library_malloc = NEWNULLPTR;
static TypeRealloc s_library_realloc = NEWNULLPTR;
static TypeCalloc s_library_calloc = NEWNULLPTR;
static TypeFreeLib s_library_free = NEWNULLPTR;

static void* malloc_uses_mmap(enum HookType,size_t);
static void* calloc_uses_mmap(size_t,size_t);

static void* s_pLibraryC = NEWNULLPTR;
#endif

/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/



typedef void (*TYPE_SIG_HANDLER)(int sigNum, siginfo_t * sigInfo, void * stackInfo);

struct SMemoryItemPrivate{
    struct MemoryItem userItem;
    SMemoryItemPrivate *prev, *next;
    void *vBacktraceCrt[STACK_MAX_SIZE], *vBacktraceDel[STACK_MAX_SIZE];
    uint64_t isDeleted : 1;
    uint64_t bitwiseReserved : 63 ;
    int32_t stackDeepCrt, stackDeepDel;
};

struct SMemoryHeader{
    //struct SMemoryItemPrivate* pItem;
    uint64_t size;
    uint64_t type : 5;
    uint64_t signature : 59;
};

static void CrashAnalizerMemHookFunction(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_pMemorForRealloc);
static void AnalizeBadMemoryCase(void* a_memoryJustCreatedOrWillBeFreed) __attribute__ ((noreturn));
static BOOL_T_2 UserHookFunctionDefault(enum HookType type,void* memoryCreatedOrWillBeFreed, size_t size, void* _memoryForRealloc);

static void* malloc_general(enum HookType a_type,size_t a_size);
static void  free_general(enum HookType,void*);

static void* malloc_for_user_not_locked(enum HookType,size_t);
static void* calloc_for_user_not_locked(size_t,size_t);
static void* realloc_for_user_not_locked(void*,size_t);
static void  free_for_user_not_locked(enum HookType,void*);

static void* malloc_calls_libc(enum HookType,size_t);
static void* calloc_calls_libc(size_t,size_t);
static void* realloc_no_user_at_all(void*,size_t);
static void  free_no_user_at_all(enum HookType,void*);


static TypeHookFunction s_MemoryHookFunction = &UserHookFunctionDefault;
static pthread_rwlock_t s_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct sigaction s_sigSegvActionOld;


static TypeMalloc2 s_malloc_aktual = &malloc_for_user_not_locked;
static TypeRealloc s_realloc_aktual = &realloc_for_user_not_locked;
static TypeCalloc s_calloc_aktual = &calloc_for_user_not_locked;
static TypeFree2 s_free_aktual = &free_for_user_not_locked;

static pthread_t s_lockerThread = 0;

END_C_DECL_2

#ifdef __cplusplus

void* operator new (size_t a_size)
{
    return malloc_general(HookTypeNewCpp,a_size);
}


void operator delete (void* a_ptr) noexcept
{
    free_general(HookTypeDeleteCpp,a_ptr);
}

void* operator new[] (size_t a_size)
{
    return malloc_general(HookTypeNewArrayCpp,a_size);
}


void operator delete[] (void* a_ptr) noexcept
{
    free_general(HookTypeDeleteArrayCpp,a_ptr);
}

void operator delete (void* a_ptr, size_t)
{
    free_general(HookTypeDeleteCpp,a_ptr);
}

void operator delete[] (void* a_ptr,size_t)
{
    free_general(HookTypeDeleteArrayCpp,a_ptr);
}

#endif  // #ifdef __cplusplus

BEGIN_C_DECL_2

/*/////////////////////////////////////////////////////////////////////////*/


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
IS_STATIC void* hooked_malloc(size_t a_size, const void* a_nextMem)
{    
#pragma GCC diagnostic pop
    return malloc_general(HookTypeMallocC,a_size);
}


#ifndef USE_MEMORY_HOOKS
void* calloc(size_t a_num, size_t a_size)
{
    void* pReturn = NEWNULLPTR;
    int isLockedHere = 0;
    pthread_t thisThread = pthread_self();

    if(s_lockerThread != thisThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
        InitializeCrashAnalizer();
    }

    pReturn = (*s_calloc_aktual)(a_num,a_size);

    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }

    return pReturn;
}
#endif  // #ifndef USE_MEMORY_HOOKS


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
IS_STATIC void* hooked_realloc(void *a_ptr, size_t a_size,const void* a_nextMem)
{    
#pragma GCC diagnostic pop
    void* pReturn = NEWNULLPTR;
    int isLockedHere = 0;
    pthread_t thisThread = pthread_self();

    if(s_lockerThread != thisThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
        InitializeCrashAnalizer();
    }

    pReturn = (*s_realloc_aktual)(a_ptr,a_size);

    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }

    return pReturn;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
IS_STATIC void hooked_free(void *a_ptr, const void* a_nextMem)
{    
#pragma GCC diagnostic pop
    if(a_ptr){
        free_general(HookTypeFreeC,a_ptr);
    }
}

/*/////////////////////////////////////////////////////////////////////////*/


static void* malloc_general(enum HookType a_type,size_t a_size)
{
    void* pReturn = NEWNULLPTR;
    int isLockedHere = 0;
    pthread_t thisThread = pthread_self();

    if(thisThread!=s_lockerThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
        InitializeCrashAnalizer();
    }

    pReturn = (*s_malloc_aktual)(a_type,a_size);

    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }

    return pReturn;
}


static void free_general(enum HookType a_type,void* a_ptr)
{
    int isLockedHere = 0;
    pthread_t thisThread = pthread_self();

    if(thisThread!=s_lockerThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
    }

    (*s_free_aktual)(a_type,a_ptr);

    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }
}


/*//////////////////////////////////////////////////////////////////*/
static void* malloc_for_user_not_locked(enum HookType a_type,size_t a_size)
{
    void* pReturn = NEWNULLPTR;

    s_malloc_aktual = &malloc_calls_libc;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_calls_libc;
    s_free_aktual = &free_no_user_at_all;

    pReturn = malloc_calls_libc(a_type,a_size);

    s_malloc_aktual = &malloc_for_user_not_locked;
    s_realloc_aktual = &realloc_for_user_not_locked;
    s_calloc_aktual = &calloc_for_user_not_locked;
    s_free_aktual = &free_for_user_not_locked;

    CrashAnalizerMemHookFunction(a_type,pReturn,a_size,NEWNULLPTR);

    return pReturn;
}


static void* calloc_for_user_not_locked(size_t a_num, size_t a_size)
{
    void* pReturn = NEWNULLPTR;

    s_malloc_aktual = &malloc_calls_libc;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_calls_libc;
    s_free_aktual = &free_no_user_at_all;

    pReturn = calloc_calls_libc(a_num,a_size);

    s_malloc_aktual = &malloc_for_user_not_locked;
    s_realloc_aktual = &realloc_for_user_not_locked;
    s_calloc_aktual = &calloc_for_user_not_locked;
    s_free_aktual = &free_for_user_not_locked;

    CrashAnalizerMemHookFunction(HookTypeCallocC,pReturn,a_size,NEWNULLPTR);

    return pReturn;
}


static void* realloc_for_user_not_locked(void* a_ptr,size_t a_size)
{
    void* pReturn = NEWNULLPTR;

    s_malloc_aktual = &malloc_calls_libc;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_calls_libc;
    s_free_aktual = &free_no_user_at_all;

    pReturn = realloc_no_user_at_all(a_ptr,a_size);

    s_malloc_aktual = &malloc_for_user_not_locked;
    s_realloc_aktual = &realloc_for_user_not_locked;
    s_calloc_aktual = &calloc_for_user_not_locked;
    s_free_aktual = &free_for_user_not_locked;

    CrashAnalizerMemHookFunction(HookTypeReallocC,pReturn,a_size,NEWNULLPTR);

    return pReturn;
}



static void  free_for_user_not_locked(enum HookType a_type, void* a_ptr)
{
    s_malloc_aktual = &malloc_for_user_not_locked;
    s_realloc_aktual = &realloc_for_user_not_locked;
    s_calloc_aktual = &calloc_for_user_not_locked;
    s_free_aktual = &free_for_user_not_locked;

    CrashAnalizerMemHookFunction(a_type,a_ptr,0,NEWNULLPTR);

    s_malloc_aktual = &malloc_calls_libc;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_calls_libc;
    s_free_aktual = &free_no_user_at_all;

    free_no_user_at_all(a_type,a_ptr);

    s_malloc_aktual = &malloc_for_user_not_locked;
    s_realloc_aktual = &realloc_for_user_not_locked;
    s_calloc_aktual = &calloc_for_user_not_locked;
    s_free_aktual = &free_for_user_not_locked;
}


/*//////////////////////////////////////////////////////*/

#define IS_MEMORY_FROM_HERE(_memHeader) ( (_memHeader)->signature==MEMORY_SIGNATURE )
#define MY_MAX_(_num1,_num2)  ( (_num1)>(_num2)?(_num1):(_num2) )

#define GRANULARITY_MIN1    63
#define GRANULARITY         64

#define USER_BUFFER_TO_HEADER(_userBuffer)  REINTERPRET_CAST(struct SMemoryHeader*,STATIC_CAST(char*,(_userBuffer))-GRANULARITY)
#define HEADER_TO_USER_BUFFER(_rawBuffer)   STATIC_CAST(void*,REINTERPRET_CAST(char*,(_rawBuffer))+GRANULARITY)

#define SIZE_BASED_ON_GRANULARITIY(_size,_gran,_granMin1)   ((_size)+(_granMin1))/(_gran)*(_gran)
#define SIZE_BASED_ON_2_GRANULARITIES(_size,_gran1,_gran2)  SIZE_BASED_ON_GRANULARITIY(_size,MY_MAX_(_gran1,_gran2),(MY_MAX_(_gran1,_gran2)-1))

//#define ALLOC_SIZE_ON_SIZE(_size)   (_size + sizeof(struct SMemoryHeader))
//#define ALLOC_SIZE_ON_SIZE(_size)   (_size + 4096)
//static inline size_t ALLOC_SIZE_ON_SIZE(size_t a_size);
#define ALLOC_SIZE_ON_SIZE(_size)   ( GRANULARITY + SIZE_BASED_ON_GRANULARITIY(_size,GRANULARITY,GRANULARITY_MIN1) )

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void* malloc_calls_libc(enum HookType a_type,size_t a_size)
{    
#pragma GCC diagnostic pop
    struct SMemoryHeader* pHeader;
    size_t unAllocSize = ALLOC_SIZE_ON_SIZE(a_size);
#ifdef USE_MEMORY_HOOKS
    char* pcReturn;
    TypeMallocHook malloc_hook_in = __malloc_hook;
    TypeReallocHook realloc_hook_in= __realloc_hook;
    TypeFreeHook free_hook_in= __free_hook;
    __malloc_hook = s_malloc_hook_initial;
    __realloc_hook = s_realloc_hook_initial;
    __free_hook = s_free_hook_initial;
    pcReturn = STATIC_CAST(char*,malloc(unAllocSize));
    __malloc_hook = malloc_hook_in;
    __realloc_hook = realloc_hook_in;
    __free_hook = free_hook_in;
#else
    char* pcReturn = STATIC_CAST(char*,(*s_library_malloc)(unAllocSize));
#endif

    if(!pcReturn){return NEWNULLPTR;}
    pHeader = REINTERPRET_CAST(struct SMemoryHeader*,pcReturn);
    pHeader->type = MEMOR_TYPE_REGULAR;
    pHeader->size = a_size;
    pHeader->signature =MEMORY_SIGNATURE;
    //pHeader->pItem = NEWNULLPTR;

    return HEADER_TO_USER_BUFFER(pcReturn);
}


static void* calloc_calls_libc(size_t a_itemsNumber, size_t a_ItemsSize)
{
    struct SMemoryHeader* pHeader;
    size_t unSize = a_itemsNumber*a_ItemsSize;
    size_t unAllocSize = SIZE_BASED_ON_2_GRANULARITIES(unSize,GRANULARITY,a_ItemsSize) + GRANULARITY;
    size_t unNewItemsNum = unAllocSize/a_ItemsSize + 1;
#ifdef USE_MEMORY_HOOKS
    char* pcReturn;
    TypeMallocHook malloc_hook_in = __malloc_hook;
    TypeReallocHook realloc_hook_in= __realloc_hook;
    TypeFreeHook free_hook_in= __free_hook;
    __malloc_hook = s_malloc_hook_initial;
    __realloc_hook = s_realloc_hook_initial;
    __free_hook = s_free_hook_initial;
    pcReturn = STATIC_CAST(char*,calloc(unNewItemsNum,a_ItemsSize));
    __malloc_hook = malloc_hook_in;
    __realloc_hook = realloc_hook_in;
    __free_hook = free_hook_in;
#else
    char* pcReturn = STATIC_CAST(char*,(*s_library_calloc)(unNewItemsNum,a_ItemsSize));
#endif

    if(!pcReturn){return NEWNULLPTR;}
    pHeader = REINTERPRET_CAST(struct SMemoryHeader*,pcReturn);
    pHeader->type = MEMOR_TYPE_REGULAR;
    pHeader->size = unSize;
    pHeader->signature =MEMORY_SIGNATURE;
    //pHeader->pItem = NEWNULLPTR;

    return HEADER_TO_USER_BUFFER(pcReturn);
}


static void* realloc_no_user_at_all(void* a_ptr,size_t a_size)
{
    void* pReturn=NEWNULLPTR;
    struct SMemoryHeader* pHeader;
    size_t unAllocSize = ALLOC_SIZE_ON_SIZE(a_size);
    char* pcReturn = NEWNULLPTR;

#ifdef USE_MEMORY_HOOKS
    TypeMallocHook malloc_hook_in = __malloc_hook;
    TypeReallocHook realloc_hook_in= __realloc_hook;
    TypeFreeHook free_hook_in= __free_hook;
    __malloc_hook = s_malloc_hook_initial;
    __realloc_hook = s_realloc_hook_initial;
    __free_hook = s_free_hook_initial;
#endif

    if(a_ptr){
        pHeader = USER_BUFFER_TO_HEADER(a_ptr);

        if(IS_MEMORY_FROM_HERE(pHeader)){
#ifdef USE_MEMORY_HOOKS
            pcReturn = STATIC_CAST(char*,realloc(pHeader,unAllocSize));
#else
            switch(pHeader->type){
            case MEMOR_TYPE_REGULAR:
                pcReturn = STATIC_CAST(char*,(*s_library_realloc)(pHeader,unAllocSize));
                break;
            case MEMOR_TYPE_MMAP:
            {
                int fd = open("/dev/zero", O_RDWR);
                size_t previousSize;
                if(fd<=0){return NEWNULLPTR;}
                // todo: ANONYMOUS mapping shold be used mmap(NEWNULLPTR, 100, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                pcReturn = STATIC_CAST(char*, mmap(NEWNULLPTR, unAllocSize, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0));
                close(fd);
                if(!pcReturn){return NEWNULLPTR;}
                previousSize = pHeader->size;
                memcpy(pcReturn+sizeof(struct SMemoryHeader),a_ptr,previousSize);
                munmap(pHeader,previousSize);
            }
                break;
            case MEMOR_TYPE_POOL:
                break;
            default:
                return (*s_library_realloc)(a_ptr,a_size);
            }
#endif
        }
        else{
#ifdef USE_MEMORY_HOOKS
            pcReturn = STATIC_CAST(char*,realloc(a_ptr,a_size));
#else
            return (*s_library_realloc)(a_ptr,a_size);
#endif
        }
    }
    else{
#ifdef USE_MEMORY_HOOKS
        pcReturn = STATIC_CAST(char*,realloc(NEWNULLPTR,unAllocSize));
#else
        pcReturn = STATIC_CAST(char*,(*s_library_realloc)(NEWNULLPTR,unAllocSize));
#endif
    }


    if(!pcReturn){goto returnPoint;}
    pHeader = REINTERPRET_CAST(struct SMemoryHeader*,pcReturn);
    pHeader->type = MEMOR_TYPE_REGULAR;
    pHeader->size = a_size;
    pHeader->signature =MEMORY_SIGNATURE;
    //pHeader->pItem = NEWNULLPTR;

    pReturn = HEADER_TO_USER_BUFFER(pcReturn);
returnPoint:
#ifdef USE_MEMORY_HOOKS
    __malloc_hook = malloc_hook_in;
    __realloc_hook = realloc_hook_in;
    __free_hook = free_hook_in;
#endif
    return pReturn;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void  free_no_user_at_all(enum HookType a_type, void* a_ptr)
{
#pragma GCC diagnostic pop

    if(a_ptr){
        struct SMemoryHeader* pHeader;
#ifdef USE_MEMORY_HOOKS
        TypeMallocHook malloc_hook_in = __malloc_hook;
        TypeReallocHook realloc_hook_in= __realloc_hook;
        TypeFreeHook free_hook_in= __free_hook;
        __malloc_hook = s_malloc_hook_initial;
        __realloc_hook = s_realloc_hook_initial;
        __free_hook = s_free_hook_initial;
#endif
        pHeader = USER_BUFFER_TO_HEADER(a_ptr);
        if(IS_MEMORY_FROM_HERE(pHeader)){            
#ifdef USE_MEMORY_HOOKS
            free(pHeader);
#else
            switch(pHeader->type){
            case MEMOR_TYPE_REGULAR:
                if(s_library_free){
                    (*s_library_free)(pHeader);
                }
                else{
                    //AddSMemoryItemToList()
                    // todo:
                }
                break;
            case MEMOR_TYPE_MMAP:
            {
                size_t previousSize= pHeader->size;
                munmap(pHeader,previousSize);
            }
                break;
            case MEMOR_TYPE_POOL:
                break;
            default:
                (*s_library_free)(a_ptr);
            }
#endif
        }
#ifdef USE_MEMORY_HOOKS
        __malloc_hook = malloc_hook_in;
        __realloc_hook = realloc_hook_in;
        __free_hook = free_hook_in;
#endif
    }

}


/*///////////////////////////////////////////////////////////////////////////////////////////////////////////*/
#ifndef USE_MEMORY_HOOKS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void* malloc_uses_mmap(enum HookType a_type,size_t a_size)
{    
#pragma GCC diagnostic pop
    struct SMemoryHeader* pHeader;
    char* pcReturn;
    size_t unAllocSize = ALLOC_SIZE_ON_SIZE(a_size);
    int fd = open("/dev/zero", O_RDWR);

    if(fd<=0){return NEWNULLPTR;}
    pcReturn = STATIC_CAST(char*, mmap(NEWNULLPTR, unAllocSize, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0));
    close(fd);
    if(!pcReturn){return NEWNULLPTR;}
    pHeader = REINTERPRET_CAST(struct SMemoryHeader*,pcReturn);
    pHeader->type = MEMOR_TYPE_REGULAR;
    pHeader->size = a_size;
    pHeader->signature =MEMORY_SIGNATURE;
    //pHeader->pItem = NEWNULLPTR;

    return HEADER_TO_USER_BUFFER(pcReturn);
}


static void* calloc_uses_mmap(size_t a_num, size_t a_size)
{
    size_t sizeForMalloc = a_num*a_size;
    void* pReturn = malloc_uses_mmap(HookTypeCallocC,sizeForMalloc);

    if(!pReturn){return NEWNULLPTR;}
    memset(pReturn,0,sizeForMalloc);
    return pReturn;
}

#endif // #ifndef USE_MEMORY_HOOKS



#define PRE_LAST_SYMBOL_INDEX   8
#define LAST_SYMBOL_INDEX       9

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void SigSegvHandler(int a_nSigNum, siginfo_t * a_pSigInfo, void * a_pStackInfo)
{    
#pragma GCC diagnostic pop
#if 1
    //int nMemoryAllocationType = s_nMemoryAllocationType;
    //s_nMemoryAllocationType = MEMOR_TYPE_INTERNAL;
    printf("Segmentation fault handler: sigNum=%d,sigInfoPtr=%p,context=%p,faulyAddress=%p\n",a_nSigNum,static_cast<void*>(a_pSigInfo),a_pStackInfo,a_pSigInfo->si_addr);
    //s_nMemoryAllocationType = nMemoryAllocationType;
    AnalizeBadMemoryCase(a_pSigInfo->si_addr);
#endif
}


TypeHookFunction SetMemoryInvestigator(TypeHookFunction a_newFnc)
{
    TypeHookFunction fpRet = s_MemoryHookFunction;
    s_MemoryHookFunction = a_newFnc;
    return fpRet;
}

void CleanupCrashAnalizer(void)
{
}


BOOL_T_2 InitializeCrashAnalizer(void)
{    
#ifdef USE_MEMORY_HOOKS

    int nReturn = 0;
    pthread_t thisThread ;
    int isLockedHere ;
    struct sigaction sigAction;

    if(s_nLibraryInited){
        return 1;
    }

    isLockedHere = 0;
    thisThread = pthread_self();

    if(thisThread!=s_lockerThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
    }


    s_malloc_hook_initial = __malloc_hook;
    s_realloc_hook_initial = __realloc_hook;
    s_free_hook_initial = __free_hook;

    __malloc_hook = &hooked_malloc;
    __realloc_hook = &hooked_realloc;
    __free_hook = &hooked_free;

    sigemptyset(&sigAction.sa_mask);
    sigAction.sa_flags = STATIC_CAST(int,SA_SIGINFO|SA_RESETHAND);
    sigAction.sa_sigaction = STATIC_CAST(TYPE_SIG_HANDLER,SigSegvHandler);
    sigaction(SIGSEGV, &sigAction, &s_sigSegvActionOld);

    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }
    s_nLibraryInited = 1;
    nReturn = 1;
    return nReturn;


#else    // #ifdef USE_MEMORY_HOOKS
    int nReturn = 0;
    TypeMalloc2 malloc_aktual = s_malloc_aktual;
    TypeRealloc realloc_aktual = s_realloc_aktual;
    TypeCalloc calloc_aktual = s_calloc_aktual;
    TypeFree2 free_aktual = s_free_aktual;
    struct sigaction sigAction;
    char lastSymb, preLastSymb;;
    char vcLibCName[32] = "libc.so.6X";
    int isLockedHere ;
    pthread_t thisThread ;

    if(s_pLibraryC){
        return 1;
    }

    isLockedHere = 0;
    thisThread = pthread_self();

    if(thisThread!=s_lockerThread){
        pthread_rwlock_wrlock(&s_rw_lock);
        s_lockerThread = thisThread;
        isLockedHere = 1;
    }

    s_malloc_aktual = &malloc_uses_mmap;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_uses_mmap;
    s_free_aktual = &free_no_user_at_all;


    //s_library_malloc = REINTERPRET_CAST(TypeMalloc,dlsym(RTLD_NEXT, "malloc"));  /* returns the object reference for malloc */
    s_pLibraryC = dlopen("libc.so",RTLD_LAZY);
    vcLibCName[LAST_SYMBOL_INDEX] = 0;
    for(preLastSymb='0';(preLastSymb<='9')&&(!s_pLibraryC);++preLastSymb){
        vcLibCName[PRE_LAST_SYMBOL_INDEX] = preLastSymb;
        s_pLibraryC = dlopen(vcLibCName,RTLD_LAZY);
    }

    for(preLastSymb='0';(preLastSymb<='9')&&(!s_pLibraryC);++preLastSymb){
        vcLibCName[PRE_LAST_SYMBOL_INDEX] = preLastSymb;
        for(lastSymb='0';(lastSymb<='9')&&(!s_pLibraryC);++lastSymb){
            vcLibCName[LAST_SYMBOL_INDEX] = lastSymb;
            s_pLibraryC = dlopen(vcLibCName,RTLD_LAZY);
        }

    }
    if(!s_pLibraryC){
        goto returnPoint;
    }
    s_library_malloc = REINTERPRET_CAST(TypeMallocLib,dlsym(s_pLibraryC, "malloc"));  /* returns the object reference for malloc */
    s_library_realloc = REINTERPRET_CAST(TypeRealloc,dlsym(s_pLibraryC, "realloc"));  /* returns the object reference for realloc */
    s_library_calloc = REINTERPRET_CAST(TypeCalloc,dlsym(s_pLibraryC, "calloc"));  /* returns the object reference for calloc */
    s_library_free = REINTERPRET_CAST(TypeFreeLib,dlsym(s_pLibraryC, "free"));  /* returns the object reference for free */
    if((!s_library_malloc)||(!s_library_realloc)||(!s_library_calloc)||(!s_library_free)){
        goto returnPoint;
    }

    sigemptyset(&sigAction.sa_mask);
    sigAction.sa_flags = STATIC_CAST(int,SA_SIGINFO|SA_RESETHAND);
    sigAction.sa_sigaction = STATIC_CAST(TYPE_SIG_HANDLER,SigSegvHandler);
    sigaction(SIGSEGV, &sigAction, &s_sigSegvActionOld);

    nReturn = 1;
returnPoint:
    s_malloc_aktual = malloc_aktual;
    s_realloc_aktual = realloc_aktual;
    s_calloc_aktual = calloc_aktual;
    s_free_aktual = free_aktual;
    if(isLockedHere){
        s_lockerThread = 0;
        pthread_rwlock_unlock(&s_rw_lock);
    }
    return nReturn;

#endif // #ifdef USE_MEMORY_HOOKS
}


/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/



//#define INTERNAL_BUFFER_REALLOC_SIZE   16384
//static size_t s_nInternalBufferSize = 0;
//static char* s_pcInternalBuffer = NEWNULLPTR;


static struct SMemoryItemList{struct SMemoryItemPrivate * first, *last;} s_existing={NEWNULLPTR,NEWNULLPTR}, s_deleted={NEWNULLPTR,NEWNULLPTR}/*, s_forInitDelete={NEWNULLPTR,NEWNULLPTR}*/;
static int s_nSizeInDeleted = 0;


//static void*

static void AddSMemoryItemToList(struct SMemoryItemPrivate * a_pItem, struct SMemoryItemList* a_pList)
{
    // todo: analize here is needed?

    /*///////////////////////////////////////////////////////////////////////////////////////////*/
    a_pItem->prev = a_pList->last;
    a_pItem->next = NEWNULLPTR;

    if(a_pList->first){
        a_pList->last->next = a_pItem;
    }
    else{
        a_pList->first = a_pItem;
    }
    a_pList->last = a_pItem;

}

static void RemoveSMemoryItemFromList(struct SMemoryItemPrivate * a_pItem, struct SMemoryItemList* a_pList)
{
    if(a_pItem==a_pList->first){
        a_pList->first = a_pItem->next;
    }
    if(a_pItem==a_pList->last){
        a_pList->last = a_pItem->prev;
    }

    if(a_pItem->prev){
        a_pItem->prev->next = a_pItem->next;
    }
    if(a_pItem->next){
        a_pItem->next->prev = a_pItem->prev;
    }

}

static struct SMemoryItemPrivate* FindMemoryItem(void* a_memoryJustCreatedOrWillBeFreed, struct SMemoryItemList* a_pList)
{
    char* pAddressToRemove = STATIC_CAST(char*,a_memoryJustCreatedOrWillBeFreed);
    struct SMemoryItemPrivate* pItem=a_pList->first;
    while(pItem){
        if(pItem->userItem.startingAddress==pAddressToRemove){
            return pItem;
        }
        pItem = pItem->next;
    }

    return NEWNULLPTR;
}


static void CrashAnalizerMemHookFunction(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_pMemorForRealloc)
{
    // enum MemoryType {createdByMalloc,createdByNew, createdByNewArray};
    // enum HookType {HookTypeMallocC, HookTypeCallocC, HookTypeReallocC, HookTypeFreeC,HookTypeNewCpp,HookTypeDeleteCpp,HookTypeNewArrayCpp,HookTypeDeleteArrayCpp};
    static int sisFirstCall=1;
    struct SMemoryItemPrivate* pItem=NEWNULLPTR;
    int nIsFirstCall = sisFirstCall;
    BOOL_T_2 bContinue;
    BOOL_T_2 isAdding = 0;
    enum MemoryType memoryType = CreatedByMalloc;
#ifdef USE_MEMORY_HOOKS
    TypeMallocHook malloc_hook_in = __malloc_hook;
    TypeReallocHook realloc_hook_in= __realloc_hook;
    TypeFreeHook free_hook_in= __free_hook;
#else
    TypeMalloc2 malloc_aktual = s_malloc_aktual;
    TypeRealloc realloc_aktual = s_realloc_aktual;
    TypeCalloc calloc_aktual = s_calloc_aktual;
    TypeFree2 free_aktual = s_free_aktual;
#endif

    sisFirstCall = 0;

    if(nIsFirstCall){
        bContinue = (*s_MemoryHookFunction)(a_type,a_memoryJustCreatedOrWillBeFreed,a_size,a_pMemorForRealloc);
        if(!bContinue){
            goto returnPoint;
        }
    }

#ifdef USE_MEMORY_HOOKS
    __malloc_hook = s_malloc_hook_initial;
    __realloc_hook = s_realloc_hook_initial;
    __free_hook = s_free_hook_initial;
#else
    s_malloc_aktual = &malloc_calls_libc;
    s_realloc_aktual = &realloc_no_user_at_all;
    s_calloc_aktual = &calloc_calls_libc;
    s_free_aktual = &free_no_user_at_all;    
#endif

    switch(a_type){
    case HookTypeMallocC: case HookTypeCallocC: case HookTypeReallocC:
        memoryType = CreatedByMalloc;
        isAdding = 1;
        break;
    case HookTypeNewCpp:
        memoryType = CreatedByNew;
        isAdding = 1;
        break;
    case HookTypeNewArrayCpp:
        memoryType = CreatedByNewArray;
        isAdding = 1;
        break;
    case HookTypeFreeC: case HookTypeDeleteCpp:case HookTypeDeleteArrayCpp:
        pItem = FindMemoryItem(a_memoryJustCreatedOrWillBeFreed, &s_existing);
        if(!pItem){
            fprintf(stderr, "!!!!!! Trying to delete non existing memory!\n");
            AnalizeBadMemoryCase(a_memoryJustCreatedOrWillBeFreed);
            goto returnPoint;
        }
        if(
                ((a_type==HookTypeFreeC)&&(pItem->userItem.type!=CreatedByMalloc)) ||
                ((a_type==HookTypeDeleteCpp)&&(pItem->userItem.type!=CreatedByNew)) ||
                ((a_type==HookTypeDeleteArrayCpp)&&(pItem->userItem.type!=CreatedByNewArray))    ){
            fprintf(stderr, "!!!!!! Trying to deallocate using non consistent function!\n");
            // todo: shall Application be crashed?
            AnalizeBadMemoryCase(a_memoryJustCreatedOrWillBeFreed);
            goto returnPoint;
        }
        pItem->isDeleted = 1;
        RemoveSMemoryItemFromList(pItem,&s_existing);
        pItem->stackDeepDel = backtrace(pItem->vBacktraceDel,STACK_MAX_SIZE);
        AddSMemoryItemToList(pItem,&s_deleted);
        if(++s_nSizeInDeleted>=MAX_NUMBER_OF_DELETED_ITEMS){
            pItem = s_existing.first;
            RemoveSMemoryItemFromList(pItem,&s_existing);
#ifdef USE_MEMORY_HOOKS
            free(pItem);
#else
            (*s_library_free)(pItem);
#endif
        }
        break;
    //default:
    //    break;
    }

    if(isAdding){
#ifdef USE_MEMORY_HOOKS
        pItem = STATIC_CAST(struct SMemoryItemPrivate*,malloc(sizeof(struct SMemoryItemPrivate)));
#else
        pItem = STATIC_CAST(struct SMemoryItemPrivate*,(*s_library_malloc)(sizeof(struct SMemoryItemPrivate)));
#endif
        if(!pItem){
            goto returnPoint;
        }
        pItem->isDeleted = 0;
        pItem->stackDeepCrt=pItem->stackDeepDel = 0;
        pItem->stackDeepCrt = backtrace(pItem->vBacktraceCrt,STACK_MAX_SIZE);
        pItem->userItem.type = memoryType;
        pItem->userItem.startingAddress = STATIC_CAST(char*,a_memoryJustCreatedOrWillBeFreed);
        pItem->userItem.size = a_size;
        AddSMemoryItemToList(pItem,&s_existing);
    }

returnPoint:    
#ifdef USE_MEMORY_HOOKS
    __malloc_hook = malloc_hook_in;
    __realloc_hook = realloc_hook_in;
    __free_hook = free_hook_in;
#else
    s_malloc_aktual = malloc_aktual;
    s_realloc_aktual = realloc_aktual;
    s_calloc_aktual = calloc_aktual;
    s_free_aktual = free_aktual;
#endif
    sisFirstCall = nIsFirstCall;
}


static void AnalizeStackFromBacktrace(void** a_pBacktrace, int32_t a_nStackDeepness);

static void AnalizeBadMemoryCase(void* a_memoryJustCreatedOrWillBeFreed)
{
    char* pcMemoryJustCreatedOrWillBeFreed = STATIC_CAST(char*,a_memoryJustCreatedOrWillBeFreed);
    ptrdiff_t leftDiffMin=-1, rightDiffMin=-1, diffCurrentLeft, diffCurrentRight;
    struct SMemoryItemPrivate *pLeftMin=NEWNULLPTR, *pRightMin=NEWNULLPTR, *pCurrent;
    int isInsideExisting=0, isInsideDeleted=0, isLeftMinFromDeleted=0, isRightMinFromDeleted=0;
    int nFailedBacktraceSize;
    void* vBacktrace[STACK_MAX_SIZE];


    nFailedBacktraceSize = backtrace(vBacktrace,STACK_MAX_SIZE);
    printf("Analizing memory %p in the stack \n",a_memoryJustCreatedOrWillBeFreed);
    AnalizeStackFromBacktrace(vBacktrace,nFailedBacktraceSize);

    pCurrent=s_existing.first;
    while(pCurrent){
        diffCurrentLeft = pCurrent->userItem.startingAddress-pcMemoryJustCreatedOrWillBeFreed;
        diffCurrentRight = pcMemoryJustCreatedOrWillBeFreed-(pCurrent->userItem.startingAddress+pCurrent->userItem.size);
        if((diffCurrentLeft<=0)&&(diffCurrentRight<=0)){
            isInsideExisting = 1;
            goto analizePoint;
        }
        else if(diffCurrentLeft<=0){
            if((rightDiffMin<0)||(diffCurrentRight<rightDiffMin)){
                rightDiffMin = diffCurrentRight;
                pRightMin = pCurrent;
            }

        }
        else{
            if((leftDiffMin<0)||(diffCurrentLeft<leftDiffMin)){
                leftDiffMin = diffCurrentLeft;
                pLeftMin = pCurrent;
            }
        }
        pCurrent = pCurrent->next;
    }

    pCurrent=s_deleted.first;
    while(pCurrent){
        diffCurrentLeft = pCurrent->userItem.startingAddress-pcMemoryJustCreatedOrWillBeFreed;
        diffCurrentRight = pcMemoryJustCreatedOrWillBeFreed-(pCurrent->userItem.startingAddress+pCurrent->userItem.size);
        if((diffCurrentLeft<=0)&&(diffCurrentRight<=0)){
            isInsideDeleted = 1;
            goto analizePoint;
        }
        else if(diffCurrentLeft<=0){
            if((rightDiffMin<0)||(diffCurrentRight<rightDiffMin)){
                rightDiffMin = diffCurrentRight;
                pRightMin = pCurrent;
                isRightMinFromDeleted = 1;
            }

        }
        else{
            if((leftDiffMin<0)||(diffCurrentLeft<leftDiffMin)){
                leftDiffMin = diffCurrentLeft;
                pLeftMin = pCurrent;
                isLeftMinFromDeleted = 1;
            }
        }
        pCurrent = pCurrent->next;
    }

analizePoint:
    if(isInsideExisting){
        printf("The problematic memory is inside existing memories pool\nCreated in the following stack\n");
        AnalizeStackFromBacktrace(pCurrent->vBacktraceCrt,pCurrent->stackDeepCrt);
    }

    else if(isInsideDeleted){
        printf("The problematic memory is inside deleted memory pool\n");
        printf("Created in the following stack\n");
        AnalizeStackFromBacktrace(pCurrent->vBacktraceCrt,pCurrent->stackDeepCrt);
        printf("Deleted in the following stack\n");
        AnalizeStackFromBacktrace(pCurrent->vBacktraceDel,pCurrent->stackDeepDel);
    }
    else{
        if(pLeftMin){
            if(isLeftMinFromDeleted){
                printf("\nbigger nearest memory is deleted. Deleting stack is:\n");
                AnalizeStackFromBacktrace(pLeftMin->vBacktraceDel,pLeftMin->stackDeepDel);
            }
            printf("\nbigger nearest memory creation stack is:\n");
            AnalizeStackFromBacktrace(pLeftMin->vBacktraceCrt,pLeftMin->stackDeepCrt);
        }

        if(pRightMin){
            if(isRightMinFromDeleted){
                printf("\nsmaller nearest memory is deleted. Deleting stack is:\n");
                AnalizeStackFromBacktrace(pRightMin->vBacktraceDel,pRightMin->stackDeepDel);
            }
            printf("\nsmaller nearest memory creation stack is:\n");
            AnalizeStackFromBacktrace(pRightMin->vBacktraceCrt,pRightMin->stackDeepCrt);
        }
    }
    _Exit(1);

}





static void AnalizeStackFromBacktrace(void** a_pBacktrace, int32_t a_nStackDeepness)
{
    if(a_nStackDeepness>0){
        char** ppSymbols;
        TypeMalloc2 malloc_aktual = s_malloc_aktual;
        TypeRealloc realloc_aktual = s_realloc_aktual;
        TypeCalloc calloc_aktual = s_calloc_aktual;
        TypeFree2 free_aktual = s_free_aktual;

        s_malloc_aktual = &malloc_calls_libc;
        s_realloc_aktual = &realloc_no_user_at_all;
        s_calloc_aktual = &calloc_calls_libc;
        s_free_aktual = &free_no_user_at_all;

        if(a_nStackDeepness>2){
            a_pBacktrace += 2;
            a_nStackDeepness -= 2;
            ppSymbols = backtrace_symbols(a_pBacktrace,a_nStackDeepness);
            if(ppSymbols){
                a_nStackDeepness -= 1;
                ppSymbols += 1;
                printf("================ Stack starts ================\n");
                for(int32_t i=0; i<a_nStackDeepness; ++i)
                {
                    //printf("%p:%s\n",a_pBacktrace[i],ppSymbols[i]);
                    printf("%s\n",ppSymbols[i]);
                }
                printf("================ Stack   ends ================\n");
            }
            free(ppSymbols);
        }

        s_malloc_aktual = malloc_aktual;
        s_realloc_aktual = realloc_aktual;
        s_calloc_aktual = calloc_aktual;
        s_free_aktual = free_aktual;
    }
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static BOOL_T_2 UserHookFunctionDefault(enum HookType type,void* memoryCreatedOrWillBeFreed, size_t size, void* _memoryForRealloc){return 1;}
#pragma GCC diagnostic pop


END_C_DECL_2
