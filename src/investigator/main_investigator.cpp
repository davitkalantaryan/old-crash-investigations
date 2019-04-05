/*
 *  Copyright (C) 
 *
 *  Written by Davit Kalantaryan <davit.kalantaryan@desy.de>
 */

 /**
  *   @file       main_investigator.cpp
  *   @copyright  
  *   @brief      Source file to demonstrate crash investigator
  *   @author     Davit Kalantaryan <davit.kalantaryan@desy.de>
  *   @date       2019 Mar 30
  *   @details 
  *       Details :  ...
  */

#include <stdio.h>
#include <stdlib.h>
#include <crash_investigator.h>
#include <unistd.h>
#ifndef _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

// enum HookType {HookTypeMallocC, HookTypeCallocC, HookTypeReallocC, HookTypeFreeC,HookTypeNewCpp,HookTypeDeleteCpp,HookTypeNewArrayCpp,HookTypeDeleteArrayCpp};
static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t a_size, void*)
//static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t , void*)
{
    printf("size = %d\n",static_cast<int>(a_size));
    return 1;
}


class MyClass
{
public:
    char m_1;
};


int main()
{
    char* pMemory;
    MyClass* pMemoryCls;
    //InitializeCrashAnalizer();
    //usleep(10000000);
    //InitializeCrashAnalizer();
    SetMemoryInvestigator(&HookFunctionStatic);
    printf("Crash analizer test!\n");
    //printf("Crash analizer test!\n");

    pMemory = new char[1];
    delete [] pMemory;
    //free(pMemory);

    pMemoryCls = new MyClass[1];
    delete [] pMemoryCls;

#if 1
    for(int i=0;i<10;++i){
        void* pMemory = malloc(100);
        free(pMemory);
        sleep(5);
    }
#endif

    //CleanupCrashAnalizer();
	return 0;
}

#if 0

extern "C"{

typedef void* (*TypeMalloc)(size_t);
typedef void (*TypeFree)(void*);
static int sisRecursing = 0;

void* malloc(size_t a_size)
{
    static void* (*my_malloc)(size_t) = NULL;
    int isRec = sisRecursing;
    sisRecursing = 1;
    if (!my_malloc)
    my_malloc = (TypeMalloc)dlsym(RTLD_NEXT, "malloc");  /* returns the object reference for malloc */
    void *p = my_malloc(a_size);               /* call malloc() using function pointer my_malloc */
    //if(!isRec)printf("malloc(%d) = %p\n", (int)a_size, p);
    sisRecursing = isRec;
    return p;
}


void free(void* a_mem)
{
    static void (*my_free)(void*);
    int isRec = sisRecursing;
    sisRecursing = 1;
    if(!isRec)printf("inside shared object...\n");
    if (!my_free)
    my_free = (TypeFree)dlsym(RTLD_NEXT, "free");  /* returns the object reference for malloc */
    //if(!isRec)printf("free(%p)\n", a_mem);
    my_free(a_mem);               /* call malloc() using function pointer my_malloc */

}

}

#endif
