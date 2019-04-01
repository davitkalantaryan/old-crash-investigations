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
#include <crash_investigator.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#ifdef _WIN32
#else
#include <pthread.h>
#include <execinfo.h>
static pthread_rwlock_t s_rw_lock;
#endif


#ifdef __GNUC__
#define DO_PRAGMA(x) _Pragma (#x)
#if 0
#define PUSH_WARNING(_warning) \
    DO_PRAGMA ( GCC diagnostic push ) \
    DO_PRAGMA ( GCC diagnostic ignored #_warning )
#define POP_WARNING() DO_PRAGMA ( GCC diagnostic pop )
#endif
#define PUSH_WARNING(_warning)
#define POP_WARNING()
#endif

#ifdef __cplusplus
#define NEWNULLPTR	nullptr
#else
#define NEWNULLPTR	NULL
#define STATIC_CAST(_Type,value) (_Type)(value)
#define CONST_CAST(_Type,value)  PUSH_WARNING("-Wcast-qual")  (_Type)(value) POP_WARNING()
#define REINTERPRET_CAST(_Type,value) (_Type)(value)
#endif

#define DUMP_NOT_USED_ARGS(...)

#define MAX_NUMBER_OF_DELETED_ITEMS 16384


BEGIN_C_DECL_2

static void CrashAnalizerMemHookFunction(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_memoryForRealloc);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static BOOL_T_2 CrashInvestigator(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_memoryForRealloc){return 1;}
#pragma GCC diagnostic pop

static int s_nHookInited = 0;
static TypeHookFunction s_MemoryHookFunction = &CrashInvestigator;
int g_nVerbosity;


#ifdef _MSC_VER

#include <crtdbg.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

static _CRT_ALLOC_HOOK s_initialHook = NEWNULLPTR;

// https://github.com/Microsoft/VCSamples/blob/master/VC2010Samples/crt/crt_dbg2/crt_dbg2.c
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/crtsetallochook?view=vs-2017
static int CRT_ALLOC_HOOK_Static(
	int a_allocType,                  // _HOOK_ALLOC, _HOOK_REALLOC, and _HOOK_FREE
	void *a_userData,                 // this is valid in the case of free
	size_t a_size,                    // size of memory requested 
	int a_blockType,                  // blockType indicates the type of the memory block ('nBlockUse==_CRT_BLOCK'  internal C runtime library allocations
	long a_requestNumber,             // requestNumber is the object allocation order number of the memory block ???
	const unsigned char *a_filename,  // if available filename is the source file name where the triggering allocation operation was initiated
	int a_lineNumber                  // if available lineNumber specify the line number where the triggering allocation operation was initiated
)
{
	switch(a_allocType){
	case _HOOK_ALLOC:
		CrashAnalizerMemHookFunction(HookTypeMalloc,a_size,(void*)a_requestNumber);
		break;
	case _HOOK_REALLOC:
		break;
	case _HOOK_FREE:
		break;
	default:
		break;
	}

	return TRUE;
}


void InitializeCrashAnalizer(void)
{
	if (!s_nHookInited) {
		s_initialHook = _CrtSetAllocHook(&CRT_ALLOC_HOOK_Static);
		s_nHookInited = 1;
	}
}


void CleanupCrashAnalizer(void)
{
	if (s_nHookInited) {
		_CrtSetAllocHook(s_initialHook);
		s_nHookInited = 0;
	}
}


#elif defined(__GNUC__)

//#pragma GCC diagnostic ignored "-Wcast-qual"
#define GRANULARITY         1024
static const int GRANULARITY_MIN1 = GRANULARITY - 1;

#ifndef weak_variable
#define weak_variable
#endif

// https://github.com/lattera/glibc/blob/master/malloc/malloc.c
// there is no calloc hook, thats why always calloc will be done in the case of malloc

extern void *weak_variable (*__malloc_hook) (size_t __size, const void *);
extern void *weak_variable (*__realloc_hook) (void *__ptr, size_t __size, const void *);
extern void  weak_variable (*__free_hook) (void *__ptr,const void *);

static void * (*__malloc_hook_initial) (size_t __size, const void *) = NEWNULLPTR;
static void * (*__realloc_hook_initial) (void *__ptr,size_t __size, const void *) = NEWNULLPTR;
static void   (*__free_hook_initial) (void *__ptr, const void *) = NEWNULLPTR;

static void * my_malloc_hook_static(size_t a_size, const void * a_nextMem);
static void * my_realloc_hook_static(void *a_ptr, size_t a_size, const void * a_nextMem);
static void   my_free_hook_static(void *a_ptr, const void * a_nextMem);

static void AnalizeBadMemoryCase(void* a_memoryJustCreatedOrWillBeFreed, void** a_pBacktrace, int32_t a_nStackDeepness);


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void * my_malloc_hook_static(size_t a_size, const void * a_nextMem)
{
#pragma GCC diagnostic pop
    void* pReturn;

    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    __malloc_hook = __malloc_hook_initial;
    __realloc_hook = __realloc_hook_initial;
    __free_hook = __free_hook_initial;
    //pReturn = calloc(((a_size+GRANULARITY_MIN1)/GRANULARITY)*GRANULARITY,1);
    pReturn = malloc(((a_size+GRANULARITY_MIN1)/GRANULARITY)*GRANULARITY);
    CrashAnalizerMemHookFunction(HookTypeCallocC,pReturn,a_size,NEWNULLPTR);
    __malloc_hook = &my_malloc_hook_static;
    __realloc_hook = &my_realloc_hook_static;
    __free_hook = &my_free_hook_static;
    pthread_rwlock_unlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    return pReturn;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void * my_realloc_hook_static(void *a_ptr, size_t a_size, const void * a_nextMem)
{
#pragma GCC diagnostic pop
    void* pReturn;

    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    __malloc_hook = __malloc_hook_initial;
    __realloc_hook = __realloc_hook_initial;
    __free_hook = __free_hook_initial;
    pReturn = realloc(a_ptr,((a_size+GRANULARITY_MIN1)/GRANULARITY)*GRANULARITY);
    CrashAnalizerMemHookFunction(HookTypeReallocC,pReturn,a_size,a_ptr);
    __malloc_hook = &my_malloc_hook_static;
    __realloc_hook = &my_realloc_hook_static;
    __free_hook = &my_free_hook_static;
    pthread_rwlock_unlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    return pReturn;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void   my_free_hook_static(void *a_ptr, const void * a_nextMem)
{
#pragma GCC diagnostic pop
    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    __malloc_hook = __malloc_hook_initial;
    __realloc_hook = __realloc_hook_initial;
    __free_hook = __free_hook_initial;
    CrashAnalizerMemHookFunction(HookTypeFreeC,a_ptr,0,NEWNULLPTR);
    free(a_ptr);
    __malloc_hook = &my_malloc_hook_static;
    __realloc_hook = &my_realloc_hook_static;
    __free_hook = &my_free_hook_static;
    pthread_rwlock_unlock(&s_rw_lock);/*////////////////////////////////////////////////*/
}


void InitializeCrashAnalizer(void)
{
    if(!s_nHookInited){
        s_nHookInited = 1;

        pthread_rwlock_init(&s_rw_lock,NEWNULLPTR);

        __malloc_hook_initial = __malloc_hook;
        __realloc_hook_initial = __realloc_hook;
        __free_hook_initial = __free_hook;

        __malloc_hook=&my_malloc_hook_static;
        __realloc_hook=&my_realloc_hook_static;
        __free_hook = &my_free_hook_static;
    }
}

void CleanupCrashAnalizer(void)
{
    if(s_nHookInited){
        s_nHookInited = 0;

        pthread_rwlock_destroy(&s_rw_lock);

        __malloc_hook=__malloc_hook_initial;
        __realloc_hook=__realloc_hook_initial;
        __free_hook = __free_hook_initial;
    }
}


TypeHookFunction SetMemoryInvestigator(TypeHookFunction a_newFnc)
{
    TypeHookFunction fpRet = s_MemoryHookFunction;
    s_MemoryHookFunction = a_newFnc;
    return fpRet;
}

#endif  // #elif defined(__GNUC__)


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

    if( !(*s_MemoryHookFunction)(a_type,a_memoryJustCreatedOrWillBeFreed,a_size,a_pMemorForRealloc) ){
        return;
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

#define BACKTRACE_MALLOC_HOOK_BUFFER_SIZE   16384
static char s_vcBacktraceSymbolsBuffer[BACKTRACE_MALLOC_HOOK_BUFFER_SIZE];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void * malloc_hook_for_backtrace(size_t a_size, const void * a_nextMem)
{
    return a_size<=BACKTRACE_MALLOC_HOOK_BUFFER_SIZE ? s_vcBacktraceSymbolsBuffer : NEWNULLPTR;
}
static void * realloc_hook_for_backtrace(void *a_ptr, size_t a_size, const void * a_nextMem)
{
    return a_size<=BACKTRACE_MALLOC_HOOK_BUFFER_SIZE ? s_vcBacktraceSymbolsBuffer : NEWNULLPTR;
}
static void   free_hook_for_backtrace(void *a_ptr, const void * a_nextMem)
{
    //
}
#pragma GCC diagnostic pop


static void AnalizeStackFromBacktrace(void** a_pBacktrace, int32_t a_nStackDeepness)
{
    if(a_nStackDeepness>0){
        char** ppSymbols;
        __malloc_hook = &malloc_hook_for_backtrace;
        __realloc_hook = &realloc_hook_for_backtrace;
        __free_hook = &free_hook_for_backtrace;
        ppSymbols = backtrace_symbols(a_pBacktrace,a_nStackDeepness);
        __malloc_hook=__malloc_hook_initial;
        __realloc_hook=__realloc_hook_initial;
        __free_hook = __free_hook_initial;
        if(ppSymbols){
            for(int32_t i=0; i<a_nStackDeepness; ++i)
            {
                printf("%s\n",ppSymbols[i]);
            }
        }
    }
}


END_C_DECL_2
