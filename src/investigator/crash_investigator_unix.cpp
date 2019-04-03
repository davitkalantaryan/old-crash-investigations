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

#if 1

#ifdef __GNUC__
//#pragma GCC diagnostic ignored "-Wreserved-id-macro"
//#define DISABLE_UNUSED_PARS _Pargma()
#endif

#ifndef	_GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <crash_investigator.h>
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

#define BACKTRACE_MALLOC_HOOK_BUFFER_SIZE   16384
#define MEMOR_TYPE_REGULAR_NO_LOG 0
#define MEMOR_TYPE_REGULAR 1
#define MEMOR_TYPE_MMAP 2
#define MEMOR_TYPE_POOL 3


BEGIN_C_DECL_2

struct SMemoryHeader{
    uint64_t size;
    uint64_t type : 5;
    uint64_t reserved : 59;
};

#define FROM_BUFF_TO_HEADER(_buffer) REINTERPRET_CAST(struct SMemoryHeader*,(_buffer))
#define FROM_USER_BUFF_TO_HEADER(_buffer) REINTERPRET_CAST(struct SMemoryHeader*,STATIC_CAST(char*,_buffer)-sizeof(struct SMemoryHeader))

typedef void* (*TypeMalloc)(size_t);
typedef void* (*TypeRealloc)(void*,size_t);
typedef void* (*TypeCalloc)(size_t nmemb, size_t size);
typedef void (*TypeFree)(void*);

static void CrashAnalizerMemHookFunction(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_pMemorForRealloc);
static void AnalizeBadMemoryCase(void* a_memoryJustCreatedOrWillBeFreed, void** a_pBacktrace, int32_t a_nStackDeepness);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static BOOL_T_2 UserHookFunction(enum HookType type,void* memoryCreatedOrWillBeFreed, size_t size, void* _memoryForRealloc){return 1;}
#pragma GCC diagnostic pop

static TypeHookFunction s_MemoryHookFunction = &UserHookFunction;
static int s_nInitialized = 0;
static int s_nMemoryAllocationType = 0;  // regular=0, mmap=1, localPool=2
static TypeMalloc s_library_malloc = NEWNULLPTR;
static TypeRealloc s_library_realloc = NEWNULLPTR;
static TypeCalloc s_library_calloc = NEWNULLPTR;
static TypeFree s_library_free = NEWNULLPTR;
static pthread_rwlock_t s_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
static int s_shouldBeLocked = 1;
//static int s_isUserRoutineCall = 0;
static void* s_pLibC = NEWNULLPTR;
static char s_vcBacktraceSymbolsBuffer[BACKTRACE_MALLOC_HOOK_BUFFER_SIZE];

#define PRE_LAST_SYMBOL_INDEX   8
#define LAST_SYMBOL_INDEX       9

static inline BOOL_T_2 InitializeLibrary(void)
{
    int nMemoryAllocationType = s_nMemoryAllocationType;
    char lastSymb, preLastSymb;;
    char vcLibCName[32] = "libc.so.6X";

    if(s_nInitialized && s_pLibC){
        return 1;
    }

    s_nMemoryAllocationType = MEMOR_TYPE_MMAP;

    s_pLibC = dlopen("libc.so",RTLD_LAZY);
    vcLibCName[LAST_SYMBOL_INDEX] = 0;
    for(preLastSymb='0';(preLastSymb<='9')&&(!s_pLibC);++preLastSymb){
        vcLibCName[PRE_LAST_SYMBOL_INDEX] = preLastSymb;
        s_pLibC = dlopen(vcLibCName,RTLD_LAZY);
    }

    for(preLastSymb='0';(preLastSymb<='9')&&(!s_pLibC);++preLastSymb){
        vcLibCName[PRE_LAST_SYMBOL_INDEX] = preLastSymb;
        for(lastSymb='0';(lastSymb<='9')&&(!s_pLibC);++lastSymb){
            vcLibCName[LAST_SYMBOL_INDEX] = lastSymb;
            s_pLibC = dlopen(vcLibCName,RTLD_LAZY);
        }

    }
    if(!s_pLibC){
        s_nMemoryAllocationType = nMemoryAllocationType;
        return 0;
    }
    s_library_malloc = REINTERPRET_CAST(TypeMalloc,dlsym(s_pLibC, "malloc"));  /* returns the object reference for malloc */
    s_library_realloc = REINTERPRET_CAST(TypeRealloc,dlsym(s_pLibC, "realloc"));  /* returns the object reference for realloc */
    s_library_calloc = REINTERPRET_CAST(TypeCalloc,dlsym(s_pLibC, "calloc"));  /* returns the object reference for calloc */
    s_library_free = REINTERPRET_CAST(TypeFree,dlsym(s_pLibC, "free"));  /* returns the object reference for free */
    if((!s_library_malloc)||(!s_library_realloc)||(!s_library_calloc)||(!s_library_free)){
        s_nMemoryAllocationType = nMemoryAllocationType;
        return 0;
    }
    s_nMemoryAllocationType = nMemoryAllocationType;
    s_nInitialized = 1;
    return 1;
}


static inline void* malloc_static (size_t a_size, enum HookType a_type)
{
    int nMemoryAllocationType=s_nMemoryAllocationType;
    int shouldBeLocked = s_shouldBeLocked;
    struct SMemoryHeader* pHeader;
    char* pcReturn = NEWNULLPTR;
    size_t unAllocSize = a_size+sizeof(struct SMemoryHeader);

    s_shouldBeLocked = 0;

    if(shouldBeLocked){
        pthread_rwlock_wrlock(&s_rw_lock);
    }


    switch(nMemoryAllocationType){
    case MEMOR_TYPE_REGULAR_NO_LOG: case MEMOR_TYPE_REGULAR:
    {
        if(!InitializeLibrary()){
            goto returnPoint;
        }
        pcReturn = STATIC_CAST(char*,(*s_library_malloc)(unAllocSize));
        if(s_nMemoryAllocationType==MEMOR_TYPE_REGULAR){
            CrashAnalizerMemHookFunction(a_type,pcReturn+sizeof(struct SMemoryHeader),a_size,NEWNULLPTR);
        }
        goto returnPoint;
    }
    case MEMOR_TYPE_MMAP:
    {
        int fd = open("/dev/zero", O_RDWR);
        if(!fd){goto returnPoint;}
        pcReturn = STATIC_CAST(char*, mmap(NEWNULLPTR, unAllocSize, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0));
        close(fd);
        goto returnPoint;
    }
    case MEMOR_TYPE_POOL:
    {
        if(unAllocSize<=BACKTRACE_MALLOC_HOOK_BUFFER_SIZE){
            pcReturn = s_vcBacktraceSymbolsBuffer;
            goto returnPoint;
        }
        else{
            goto returnPoint;
        }
    }
    default:
        break;
    }


returnPoint:
    if(pcReturn){
        pHeader=FROM_BUFF_TO_HEADER(pcReturn);
        pHeader->type = STATIC_CAST(uint64_t,nMemoryAllocationType);
        pHeader->size = a_size;
        pcReturn += sizeof(struct SMemoryHeader);
    }

    s_shouldBeLocked = shouldBeLocked;

    if(shouldBeLocked){
        pthread_rwlock_unlock(&s_rw_lock);
    }

    return pcReturn;
}


void* malloc(size_t a_size)
{
    return malloc_static(a_size,HookTypeMallocC);
}

void* calloc(size_t a_nmemb, size_t a_size)
{
    void* pReturn = malloc_static(a_nmemb*a_size,HookTypeCallocC);
    if(pReturn){
        memset(pReturn,0,a_size);
    }
    return pReturn;
}


void* realloc(void *a_ptr, size_t a_size)
{
    int shouldBeLocked = s_shouldBeLocked;
    void* pReturn = NEWNULLPTR;

    s_shouldBeLocked = 0;

    if(shouldBeLocked){
        pthread_rwlock_wrlock(&s_rw_lock);
    }

    pReturn = malloc_static(a_size,HookTypeReallocC);

    if(a_ptr){
        struct SMemoryHeader* pHeader=FROM_USER_BUFF_TO_HEADER(a_ptr);
        if(pHeader->size){
            memcpy(pReturn,a_ptr,pHeader->size);
            free(a_ptr);
        }
    }

    s_shouldBeLocked=shouldBeLocked;
    if(shouldBeLocked){
        pthread_rwlock_unlock(&s_rw_lock);
    }
    return pReturn;

}



#if 1
void free(void *a_ptr)
{
    int shouldBeLocked = s_shouldBeLocked;
    struct SMemoryHeader* pHeader;

    if(!a_ptr){return;}

    pHeader=FROM_USER_BUFF_TO_HEADER(a_ptr);
    switch(pHeader->type){
    case MEMOR_TYPE_REGULAR_NO_LOG:
        CrashAnalizerMemHookFunction(HookTypeFreeC,a_ptr,0,NEWNULLPTR);
    case MEMOR_TYPE_REGULAR:
        break;
    case MEMOR_TYPE_MMAP:
        munmap(a_ptr,pHeader->size);
        break;
    case MEMOR_TYPE_POOL:
        break;
    default:
        break;
    }

#if 0
    if(!s_isFirstCall){
        if(s_isUserRoutineCall){
            CrashAnalizerMemHookFunction(HookTypeMallocC,a_ptr,0,NEWNULLPTR);
        }
        (*s_library_free)(a_ptr);
        return;
    }

    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    s_isFirstCall = 0;
    if(!s_nInitialized){
        s_library_malloc = REINTERPRET_CAST(TypeMalloc,dlsym(RTLD_NEXT, "malloc"));  /* returns the object reference for malloc */
        s_library_realloc = REINTERPRET_CAST(TypeRealloc,dlsym(RTLD_NEXT, "realloc"));  /* returns the object reference for realloc */
        s_library_calloc = REINTERPRET_CAST(TypeCalloc,dlsym(RTLD_NEXT, "calloc"));  /* returns the object reference for calloc */
        s_library_free = REINTERPRET_CAST(TypeFree,dlsym(RTLD_NEXT, "free"));  /* returns the object reference for free */
        if((!s_library_malloc)||(!s_library_realloc)||(!s_library_calloc)||(!s_library_free)){
            goto returnPoint;
        }
        s_nInitialized = 1;
    }

    (*s_library_free)(a_ptr);
    CrashAnalizerMemHookFunction(HookTypeReallocC,a_ptr,0,NEWNULLPTR);

returnPoint:
    s_isFirstCall = 1;
    pthread_rwlock_unlock(&s_rw_lock);/*////////////////////////////////////////////////*/
#endif
}
#endif



void InitializeCrashAnalizer(void)
{
    if(!s_nInitialized){
        s_library_malloc = REINTERPRET_CAST(TypeMalloc,dlsym(RTLD_NEXT, "malloc"));  /* returns the object reference for malloc */
        s_library_realloc = REINTERPRET_CAST(TypeRealloc,dlsym(RTLD_NEXT, "realloc"));  /* returns the object reference for realloc */
        s_library_calloc = REINTERPRET_CAST(TypeCalloc,dlsym(RTLD_NEXT, "calloc"));  /* returns the object reference for calloc */
        s_library_free = REINTERPRET_CAST(TypeFree,dlsym(RTLD_NEXT, "free"));  /* returns the object reference for free */
        if((!s_library_malloc)||(!s_library_realloc)||(!s_library_calloc)||(!s_library_free)){
            return;
        }
        s_nInitialized = 1;
    }
}

void CleanupCrashAnalizer(void)
{
}


TypeHookFunction SetMemoryInvestigator(TypeHookFunction a_newFnc)
{
    TypeHookFunction fpRet = s_MemoryHookFunction;
    s_MemoryHookFunction = a_newFnc;
    return fpRet;
}



/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/

#define STACK_MAX_SIZE  256

//#define INTERNAL_BUFFER_REALLOC_SIZE   16384
//static size_t s_nInternalBufferSize = 0;
//static char* s_pcInternalBuffer = NEWNULLPTR;
struct SMemoryItem{
    struct SMemoryItem *prev, *next;
    void *vBacktraceCrt[STACK_MAX_SIZE], *vBacktraceDel[STACK_MAX_SIZE];
    int32_t stackDeepCrt, stackDeepDel;
    char* startingAddress2;
    size_t size2;
    enum MemoryType type;
    int reserved;
};

static struct SMemoryItemList{struct SMemoryItem * first, *last;} s_existing={NEWNULLPTR,NEWNULLPTR}, s_deleted={NEWNULLPTR,NEWNULLPTR};
static int s_nSizeInDeleted = 0;


//static void*

static void AddSMemoryItemToList(struct SMemoryItem * a_pItem, struct SMemoryItemList* a_pList, enum MemoryType a_memoryType, void* a_pMemory, size_t a_unSize)
{
    // todo: analize here is needed?

    /*///////////////////////////////////////////////////////////////////////////////////////////*/
    a_pItem->type = a_memoryType;
    a_pItem->prev = a_pList->last;
    a_pItem->next = NEWNULLPTR;

    if(a_pList->first){
        a_pList->first->prev = a_pItem;
    }
    else{
        a_pList->first = a_pItem;
    }
    a_pList->last = a_pItem;

    a_pItem->startingAddress2 = STATIC_CAST(char*,a_pMemory);
    a_pItem->size2 = a_unSize;
}

static void RemoveSMemoryItemFromList(struct SMemoryItem * a_pItem, struct SMemoryItemList* a_pList)
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

static struct SMemoryItem* FindMemoryItem(void* a_memoryJustCreatedOrWillBeFreed, struct SMemoryItemList* a_pList)
{
    char* pAddressToRemove = STATIC_CAST(char*,a_memoryJustCreatedOrWillBeFreed);
    struct SMemoryItem* pItem=a_pList->first;
    while(pItem){
        if(pItem->startingAddress2==pAddressToRemove){
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
    static void *svBacktrace[STACK_MAX_SIZE];
    struct SMemoryItem* pItem=NEWNULLPTR;
    int32_t nFailedBacktraceSize;
    int nIsFirstCall = s_isFirstCall;
    BOOL_T_2 bContinue;

    if(!nIsFirstCall){
        bContinue = (*s_MemoryHookFunction)(a_type,a_memoryJustCreatedOrWillBeFreed,a_size,a_pMemorForRealloc);
        if(!bContinue){
            return;
        }
    }

#if 0
    char** ppSymbols = backtrace_symbols(pStack,nStackDeepness);
    if(ppSymbols){
        for(int i=0; i<nStackDeepness; ++i)
        {
            //printf("%s\n",ppSymbols[i]);
        }
        free(ppSymbols);
    }
#endif

    switch(a_type){
    case HookTypeMallocC: case HookTypeCallocC: case HookTypeReallocC:
        pItem = STATIC_CAST(struct SMemoryItem*,malloc(sizeof(struct SMemoryItem*)));
        if(!pItem){
            return;
        }
        pItem->stackDeepCrt=pItem->stackDeepDel = 0;
        pItem->stackDeepCrt = backtrace(pItem->vBacktraceCrt,STACK_MAX_SIZE);
        AddSMemoryItemToList(pItem,&s_existing,CreatedByMalloc,a_memoryJustCreatedOrWillBeFreed,a_size);
        break;
    case HookTypeFreeC:
        pItem = FindMemoryItem(a_memoryJustCreatedOrWillBeFreed, &s_existing);
        if(!pItem){
            fprintf(stderr, "!!!!!! Trying to delete non existing memory!\n");
            nFailedBacktraceSize = backtrace(svBacktrace,STACK_MAX_SIZE);
            AnalizeBadMemoryCase(a_memoryJustCreatedOrWillBeFreed,svBacktrace,nFailedBacktraceSize);
            return;
        }
        RemoveSMemoryItemFromList(pItem,&s_existing);
        pItem->stackDeepDel = backtrace(pItem->vBacktraceDel,STACK_MAX_SIZE);
        AddSMemoryItemToList(pItem,&s_deleted,CreatedByMalloc,a_memoryJustCreatedOrWillBeFreed,a_size);
        if(++s_nSizeInDeleted>=MAX_NUMBER_OF_DELETED_ITEMS){
            RemoveSMemoryItemFromList(s_existing.first,&s_existing);
        }
        break;
    default:
        break;
    }

}


static void AnalizeStackFromBacktrace(void** a_pBacktrace, int32_t a_nStackDeepness);

static void AnalizeBadMemoryCase(void* a_memoryJustCreatedOrWillBeFreed, void** a_pBacktrace, int32_t a_nStackDeepness)
{
    char* pcMemoryJustCreatedOrWillBeFreed = STATIC_CAST(char*,a_memoryJustCreatedOrWillBeFreed);
    ptrdiff_t leftDiffMin=-1, rightDiffMin=-1, diffCurrentLeft, diffCurrentRight;
    struct SMemoryItem *pLeftMin=NEWNULLPTR, *pRightMin=NEWNULLPTR, *pCurrent;
    int isInsideExisting=0, isInsideDeleted=0, isLeftMinFromDeleted=0, isRightMinFromDeleted=0;

    printf("Analizing memory %p in the stack \n",a_memoryJustCreatedOrWillBeFreed);
    AnalizeStackFromBacktrace(a_pBacktrace,a_nStackDeepness);

    pCurrent=s_existing.first;
    while(pCurrent){
        diffCurrentLeft = pCurrent->startingAddress2-pcMemoryJustCreatedOrWillBeFreed;
        diffCurrentRight = pcMemoryJustCreatedOrWillBeFreed-(pCurrent->startingAddress2+pCurrent->size2);
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
        diffCurrentLeft = pCurrent->startingAddress2-pcMemoryJustCreatedOrWillBeFreed;
        diffCurrentRight = pcMemoryJustCreatedOrWillBeFreed-(pCurrent->startingAddress2+pCurrent->size2);
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
                printf("\nbigger nearest pool is deleted. Deleting stack is:\n");
                AnalizeStackFromBacktrace(pLeftMin->vBacktraceDel,pLeftMin->stackDeepDel);
            }
            printf("\nCreation stack is:\n");
            AnalizeStackFromBacktrace(pLeftMin->vBacktraceCrt,pLeftMin->stackDeepCrt);
        }

        if(pRightMin){
            if(isRightMinFromDeleted){
                printf("\nsmaller nearest pool is deleted. Deleting stack is:\n");
                AnalizeStackFromBacktrace(pRightMin->vBacktraceDel,pRightMin->stackDeepDel);
            }
            printf("\nCreation stack is:\n");
            AnalizeStackFromBacktrace(pRightMin->vBacktraceCrt,pRightMin->stackDeepCrt);
        }
    }

    //

}





static void AnalizeStackFromBacktrace(void** a_pBacktrace, int32_t a_nStackDeepness)
{
    if(a_nStackDeepness>0){
        char** ppSymbols;
        s_nDoMallocFromLocalPool = 1;
        ppSymbols = backtrace_symbols(a_pBacktrace,a_nStackDeepness);
        if(ppSymbols){
            for(int32_t i=0; i<a_nStackDeepness; ++i)
            {
                printf("%s\n",ppSymbols[i]);
            }
        }
        free(ppSymbols);
        s_nDoMallocFromLocalPool = 0;
    }
}


END_C_DECL_2

#endif // #if 0
