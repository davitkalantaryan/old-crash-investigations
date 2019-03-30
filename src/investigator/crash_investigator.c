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

#ifdef __cplusplus
#define NEWNULLPTR	nullptr
#else
#define NEWNULLPTR	NULL
#endif


BEGIN_C_DECL_2

static void CrashAnalizerMemHookFunction(enum HookType a_type, size_t a_size, void* a_memory);

static int s_nHookInited = 0;
TypeHookFunction g_MemoryHookFunction = &CrashAnalizerMemHookFunction;


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

extern void * (*__malloc_hook) (size_t __size, const void *);
static void * (*__malloc_hook_initial) (size_t __size, const void *) = NEWNULLPTR;

static void * my_malloc_hook_static(size_t a_size, const void * a_nextMem)
{
	void* pReturn;
	__malloc_hook = __malloc_hook_initial;
	pReturn = malloc(a_size);
	__malloc_hook = &my_malloc_hook_static;
	return pReturn;
}

void InitializeCrashAnalizer(void)
{
	__malloc_hook_initial = __malloc_hook;
	__malloc_hook=&my_malloc_hook_static;
}

#endif


/*///////////////////////////////////////////////////////////////////////////////////////////////////////*/

static void CrashAnalizerMemHookFunction(enum HookType a_type, size_t a_size, void* a_memory)
{
}


END_C_DECL_2
