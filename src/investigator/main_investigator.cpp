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

//
// todo:
// https://oroboro.com/printing-stack-traces-file-line/
// (gdb) info symbol 0x4005BDC
// addr2line -e  investigator 0x189b
// gdb --silent --eval-command "info symbol 0x189b" -ex "quit" ./investigator


#include <stdio.h>
#include <stdlib.h>
#include <crash_investigator.h>
#include <unistd.h>
#ifndef _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <spawn.h>
#include <sys/ptrace.h>

static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t a_size, void*)
{
    printf("pid:%d => size = %d\n",getpid(), static_cast<int>(a_size));
    return 1;
}

extern "C" int RunCode11(char* libname, pid_t target);

int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n) {
    /* just like memcpy, but copies it into the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    for (i = 0; i < n / sizeof(long); i++) {
    if (ptrace(PTRACE_POKETEXT, pid, d+i, s[i]) == -1) {
        perror("ptrace(PTRACE_POKETEXT)");
        return 0;
    }
    }
    return 1;
}


#define weak_variable

extern void *weak_variable (*__malloc_hook) (size_t __size, const void *);
extern void *weak_variable (*__realloc_hook) (void *__ptr, size_t __size, const void *);
extern void  weak_variable (*__free_hook) (void *__ptr,const void *);
void *findRemoteSymbolAddress( const char* library, void* local_addr, pid_t pid );

#define LIBRARY_TO_SEARCH "libgcc_s.so.1"

int main(int a_argc, char* a_argv[])
{
    int nPid;

    if(a_argc<2){
        fprintf(stderr,"command to debug is not provided!\n");
        return 1;
    }

    nPid = fork();

    if(nPid){
        //long ptrace(enum __ptrace_request request, pid_t pid,void *addr, void *data);
        pid_t w;
        int status;
        enum __ptrace_setoptions options;

        InitializeCrashAnalizer();

        printf("pid=%d\n",nPid);
        //kill(nPid,SIGSTOP);
        //sleep(10);
        //RunCode11("/afs/ifh.de/user/k/kalantar/dev/sys/bionic/lib/libinject.so.1",nPid);
        //kill(nPid,SIGCONT);

        ptrace(PTRACE_ATTACH,nPid);
        wait(&status);
        options = PTRACE_O_TRACEEXEC;
        ptrace(PTRACE_SETOPTIONS ,nPid,&options);
        ptrace(PTRACE_CONT,nPid);
        sleep(1);

        void* pMallocHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__malloc_hook,nPid);
        void* pReallocHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__realloc_hook,nPid);
        void* pFreeHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__free_hook,nPid);

        memcpy_into_target(nPid,pMallocHookAddress,&__malloc_hook,sizeof(__malloc_hook));
        memcpy_into_target(nPid,pReallocHookAddress,&__realloc_hook,sizeof(__realloc_hook));
        memcpy_into_target(nPid,pFreeHookAddress,&__free_hook,sizeof(__free_hook));

        //kill(nPid,SIGCONT);
        ptrace(PTRACE_CONT,nPid);
        ptrace(PTRACE_DETACH, nPid);

        do {

            w = waitpid(nPid, &status, WUNTRACED | WCONTINUED);
            if (w == -1) {
                perror("waitpid");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                printf("exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("killed by signal %d\n", WTERMSIG(status));
            } else if (WIFSTOPPED(status)) {
                printf("stopped by signal %d\n", WSTOPSIG(status));
            } else if (WIFCONTINUED(status)) {
                printf("continued\n");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }
    else{
        //InitializeCrashAnalizer();
        //SetMemoryInvestigator(&HookFunctionStatic);
        //kill(getpid(),SIGSTOP);
        //dlopen("/afs/ifh.de/user/k/kalantar/dev/sys/bionic/lib/libinject.so.1",RTLD_LAZY);
        execvp (a_argv[1], a_argv+1);
    }

	return 0;
}

#include <string.h>




intptr_t findLibraryOffset( const char *library, pid_t pid )
{
    char filename[0xFF] = {0},
         buffer[1024] = {0};
    FILE *fp = NULL;
    intptr_t address = 0;

    sprintf( filename, "/proc/%d/maps", pid );

    fp = fopen( filename, "rt" );
    if( fp == NULL ){
        perror("fopen");
        goto done;
    }

    while( fgets( buffer, sizeof(buffer), fp ) ) {
        if( strstr( buffer, library ) ){
            address = (intptr_t)strtoul( buffer, NULL, 16 );
            goto done;
        }
    }

    done:

    if(fp){
        fclose(fp);
    }

    return address;
}

void *findRemoteSymbolAddress( const char* library, void* local_addr, pid_t pid )
{
    intptr_t local_handle, remote_handle;

    local_handle = findLibraryOffset( library, getpid() );
    remote_handle = findLibraryOffset( library,pid );

    return (void *)( (intptr_t)local_addr + (intptr_t)remote_handle - (intptr_t)local_handle );
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
