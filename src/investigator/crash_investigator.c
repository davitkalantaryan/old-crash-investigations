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
#ifdef _WIN32
#else
#include <pthread.h>
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


BEGIN_C_DECL_2

static void CrashAnalizerMemHookFunction2(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_memoryForRealloc);

static int s_nHookInited = 0;
TypeHookFunction g_MemoryHookFunction = &CrashAnalizerMemHookFunction2;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void * my_malloc_hook_static(size_t a_size, const void * a_nextMem)
{
#pragma GCC diagnostic pop
	void* pReturn;

    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/

    __malloc_hook = __malloc_hook_initial;
    pReturn = calloc(a_size,1);

    (*g_MemoryHookFunction)(HookTypeCallocC,pReturn,a_size,NEWNULLPTR);

	__malloc_hook = &my_malloc_hook_static;

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

    __realloc_hook = __realloc_hook_initial;
    pReturn = realloc(a_ptr,a_size);

    (*g_MemoryHookFunction)(HookTypeReallocC,pReturn,a_size,a_ptr);

    __realloc_hook = &my_realloc_hook_static;

    pthread_rwlock_unlock(&s_rw_lock);/*////////////////////////////////////////////////*/
    return pReturn;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void   my_free_hook_static(void *a_ptr, const void * a_nextMem)
{
#pragma GCC diagnostic pop

    pthread_rwlock_wrlock(&s_rw_lock);/*////////////////////////////////////////////////*/

    __free_hook = __free_hook_initial;

    (*g_MemoryHookFunction)(HookTypeFreeC,a_ptr,0,NEWNULLPTR);

    free(a_ptr);

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

#endif  // #elif defined(__GNUC__)


/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/

struct SMemoryItem{
    struct SMemoryItem *prev, *next;
    char** backtraceSymbols;
    ptrdiff_t startingAddress, size;
    enum MemoryType type;
    int reserved;
};

static struct SMemoryItem *s_memItemsListBeg=NEWNULLPTR;
static struct SMemoryItem *s_memItemsListEnd=NEWNULLPTR;

static struct SMemoryItem *s_memItemsListDiedBeg=NEWNULLPTR;
static struct SMemoryItem *s_memItemsListDiedEnd=NEWNULLPTR;

static void ConstructorSMemoryItem(struct SMemoryItem * a_pItem, enum MemoryType a_memoryType, void* a_pMemory, size_t a_unSize)
{
    // todo: analize here is needed?

    /*///////////////////////////////////////////////////////////////////////////////////////////*/
    a_pItem->type = a_memoryType;
    a_pItem->prev = s_memItemsListEnd;
    a_pItem->next = NEWNULLPTR;

    if(s_memItemsListBeg){
        s_memItemsListEnd->prev = a_pItem;
    }
    else{
        s_memItemsListBeg = a_pItem;
    }
    s_memItemsListEnd = a_pItem;


    a_pItem->backtraceSymbols = NEWNULLPTR;  // should be fixed


    a_pItem->startingAddress = REINTERPRET_CAST(ptrdiff_t,STATIC_CAST(char*,a_pMemory));
    a_pItem->size = STATIC_CAST(ptrdiff_t,a_unSize);
}

static void DestructorSMemoryItemPartly(struct SMemoryItem * a_pItem)
{
    if(a_pItem==s_memItemsListBeg){
        s_memItemsListBeg = a_pItem->next;
    }
    if(a_pItem==s_memItemsListEnd){
        s_memItemsListBeg = a_pItem->prev;
    }

    if(a_pItem->prev){
        a_pItem->prev->next = a_pItem->next;
    }
    if(a_pItem->next){
        a_pItem->next->prev = a_pItem->prev;
    }

#if 0
    /*//////////////////////////////////////*/
    // todo: check proper
    if(a_pItem->backtraceSymbols){
        free(a_pItem->backtraceSymbols);
    }
#endif

}

static struct SMemoryItem* FindMemoryItem(void* a_memoryJustCreatedOrWillBeFreed)
{
    struct SMemoryItem* pItem=s_memItemsListBeg;
    while(pItem){
        if(pItem->startingAddress==REINTERPRET_CAST(ptrdiff_t,a_memoryJustCreatedOrWillBeFreed)){
            return pItem;
        }
        pItem = pItem->next;
    }

    return NEWNULLPTR;
}


static void CrashAnalizerMemHookFunction2(enum HookType a_type, void* a_memoryJustCreatedOrWillBeFreed, size_t a_size, void* a_pMemorForRealloc)
{
    // enum MemoryType {createdByMalloc,createdByNew, createdByNewArray};
    // enum HookType {HookTypeMallocC, HookTypeCallocC, HookTypeReallocC, HookTypeFreeC,HookTypeNewCpp,HookTypeDeleteCpp,HookTypeNewArrayCpp,HookTypeDeleteArrayCpp};

    struct SMemoryItem* pItem;

    if(a_pMemorForRealloc && g_nVerbosity){
        printf("realloc!\n");
    }

    switch(a_type){
    case HookTypeMallocC: case HookTypeCallocC: case HookTypeReallocC:
        pItem = STATIC_CAST(struct SMemoryItem*,malloc(sizeof(struct SMemoryItem*)));
        if(!pItem){return;}
        ConstructorSMemoryItem(pItem,CreatedByMalloc,a_memoryJustCreatedOrWillBeFreed,a_size);
        break;
    case HookTypeFreeC:
        pItem = FindMemoryItem(a_memoryJustCreatedOrWillBeFreed);
        if(!pItem){
            fprintf(stderr, "!!!!!! Trying to delete non existing memory!\n");
            return;
        }
        DestructorSMemoryItemPartly(pItem);
        break;
    default:
        break;
    }
}


END_C_DECL_2
