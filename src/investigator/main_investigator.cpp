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
#define _GNU_SOURCE
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
#include <sys/user.h>
#include <memory.h>
#include <link.h>
#include <elf.h>

// https://www.i-programmer.info/programming/cc/3978-executable-code-injection-in-linux.html?start=1
// https://courses.cs.washington.edu/courses/cse378/10au/sections/Section1_recap.pdf

#ifdef __RTLD_DLOPEN
#define NEW_RTLD_DLOPEN	__RTLD_DLOPEN
#else
#define NEW_RTLD_DLOPEN	0x80000000
#endif

static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t a_size, void*)
{
    printf("pid:%d => size = %d\n",getpid(), static_cast<int>(a_size));
    return 1;
}

extern "C" int RunCode11(char* libname, pid_t target);
//#include <libexplain/ptrace.h>

int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n) {
    /* just like memcpy, but copies it into the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    for (i = 0; i < n / sizeof(long); i++) {
        //nRet =
    if (ptrace(PTRACE_POKETEXT, pid, d+i, &s[i]) == -1) {
        perror("ptrace(PTRACE_POKETEXT)");
        return 0;
    }
    }
    return 1;
}

void ptraceWrite(int pid, unsigned long long addr, const void *a_data, int len) {
    long word = 0;
    int i = 0;
    const char* data = static_cast<const char*>(a_data);

    for (i=0; i < len; i+=sizeof(word), word=0) {
      memcpy(&word, data + i, sizeof(word));
      if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {
        printf("[!] Error writing process memory\n");
        exit(1);
      }
    }
}


void ptraceRead(int pid, unsigned long long addr, void *a_data, int len) {
    long word = 0;
    int i = 0;
    char* data = static_cast<char*>(a_data);

    for (i=0; i < len; i+=sizeof(word), word=0) {
        word=ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
      memcpy(data + i,&word, sizeof(word));
    }
}


#define weak_variable

extern void *weak_variable (*__malloc_hook) (size_t __size, const void *);
extern void *weak_variable (*__realloc_hook) (void *__ptr, size_t __size, const void *);
extern void  weak_variable (*__free_hook) (void *__ptr,const void *);
void *findRemoteSymbolAddress( const char* library, void* local_addr, pid_t pid );
long freespaceaddr(pid_t pid);

#define LIBRARY_TO_SEARCH "libgcc_s.so.1"
extern "C" void *__libc_dlopen_mode  (const char *__name, int __mode);

#define LIB_TO_OPENNAME "libinject.so.1"


int main(int a_argc, char* a_argv[])
{
    Elf64_Sym *pElfDlOpen=nullptr;
    void* pMalloc=nullptr;
    int nPid;
    Dl_info dlIndoDlOpen;
    unsigned long long int ullnDlOpenSize, unStrLenPlus1, unStrLenRounded, unMallocSize;
    void *(*libc_dlopen_mode)  (const char *__name, int __mode)=&__libc_dlopen_mode;

    if(a_argc<2){
        fprintf(stderr,"command to debug is not provided!\n");
        return 1;
    }

    void* pLib = __libc_dlopen_mode("/lib/x86_64-linux-gnu/ld-2.27.so",RTLD_NOW | NEW_RTLD_DLOPEN);
    if(pLib){
        pMalloc =  dlsym(pLib,"malloc");
    }
    if(!pMalloc){
        return 1;
    }
    void* pFuncAddress = *reinterpret_cast<void**>(&libc_dlopen_mode);
    int nReturn = dladdr1(pFuncAddress,&dlIndoDlOpen,(void**)&pElfDlOpen,RTLD_DL_SYMENT);
    if((!nReturn)||(!pElfDlOpen)){
        return 2;
    }
    ullnDlOpenSize = (pElfDlOpen->st_size+7)/8*8;
    unStrLenPlus1 = strlen(LIB_TO_OPENNAME) + 1;
    unStrLenRounded = (unStrLenPlus1+7)/8*8;
    unMallocSize = ullnDlOpenSize + unStrLenRounded;

    //nReturn = dladdr(pMalloc,&dlIndo2);
    const unsigned long long int lnBrkPoint=0xcc;

    nPid = fork();

    if(nPid){
        //long ptrace(enum __ptrace_request request, pid_t pid,void *addr, void *data);
        struct user_regs_struct regs0,regs;
        pid_t w;
        int status;
        enum __ptrace_setoptions options;
        unsigned long long int ripInitial, rspInitial;

        printf("pid=%d\n",nPid);
        //kill(nPid,SIGSTOP);
        //sleep(10);
        //RunCode11("/afs/ifh.de/user/k/kalantar/dev/sys/bionic/lib/libinject.so.1",nPid);
        //kill(nPid,SIGCONT);

        ptrace(PTRACE_ATTACH,nPid);
        //waitpid(nPid,&status,0);
        options = PTRACE_O_TRACEEXEC;
        ptrace(PTRACE_SETOPTIONS ,nPid,&options);
        //kill(nPid,SIGCONT);
        ptrace(PTRACE_CONT,nPid);
        sleep(1);

        /* Here we start remote code running */
        ptrace(PTRACE_GETREGS, nPid, NULL, &regs);
        memcpy(&regs0,&regs,sizeof(regs));
        regs.rsp -= 8;
        //*reinterpret_cast<unsigned long long int*>(regs.rsp)=regs.rip; // should be written to the tracee
        ptraceRead(nPid,regs.rip,&ripInitial,sizeof(unsigned long long int));
        ptraceRead(nPid,regs.rsp,&rspInitial,sizeof(unsigned long long int));
        ptraceWrite(nPid,regs0.rip,&lnBrkPoint,sizeof(unsigned long long int));
        ptraceWrite(nPid,regs.rsp,&regs0.rip,sizeof(unsigned long long int));
        //memcpy_into_target(nPid,reinterpret_cast<void*>(regs.rip),&lnBrkPoint,sizeof(unsigned long long int));

        regs.rip = reinterpret_cast<unsigned long long int>(pMalloc);
        regs.rdi = unMallocSize;
        ptrace(PTRACE_SETREGS, nPid, NULL, &regs);
        ptrace(PTRACE_CONT,nPid);
        wait(&status);
        ptrace(PTRACE_GETREGS, nPid, NULL, &regs);
        unsigned long long int ullnMallocReturned = regs.rax; // return from malloc

        //ptraceWrite(nPid,regs0.rip,&ripInitial,sizeof(unsigned long long int));
        //ptraceWrite(nPid,regs.rsp,&rspInitial,sizeof(unsigned long long int));
        //ptrace(PTRACE_SETREGS, nPid, NULL, &regs0);
        //ptrace(PTRACE_CONT,nPid);
        //wait(&status);
        /* End of remote code running */


        /* Here we start remote code running */
        regs.rsp -= 8;

        ptraceWrite(nPid,ullnMallocReturned,pFuncAddress,pElfDlOpen->st_size);
        ptraceWrite(nPid,ullnMallocReturned+ullnDlOpenSize,LIB_TO_OPENNAME,unStrLenPlus1);
        ptraceWrite(nPid,regs0.rip,&lnBrkPoint,sizeof(unsigned long long int));
        ptraceWrite(nPid,regs.rsp,&regs0.rip,sizeof(unsigned long long int));

        regs.rip = ullnMallocReturned;
        regs.rdi = ullnMallocReturned+ullnDlOpenSize;
        regs.rsi = RTLD_NOW | NEW_RTLD_DLOPEN;

        ptrace(PTRACE_SETREGS, nPid, NULL, &regs);
        ptrace(PTRACE_CONT,nPid);
        wait(&status);

        ptraceWrite(nPid,regs0.rip,&ripInitial,sizeof(unsigned long long int));
        ptraceWrite(nPid,regs0.rsp,&rspInitial,sizeof(unsigned long long int));
        ptrace(PTRACE_SETREGS, nPid, NULL, &regs0);

        ptrace(PTRACE_CONT,nPid);
        /* End of remote code running */


#if 0

        void* pMallocHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__malloc_hook,nPid);
        void* pReallocHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__realloc_hook,nPid);
        void* pFreeHookAddress = findRemoteSymbolAddress(LIBRARY_TO_SEARCH,&__free_hook,nPid);

        memcpy_into_target(nPid,pMallocHookAddress,&__malloc_hook,sizeof(__malloc_hook));
        memcpy_into_target(nPid,pReallocHookAddress,&__realloc_hook,sizeof(__realloc_hook));
        memcpy_into_target(nPid,pFreeHookAddress,&__free_hook,sizeof(__free_hook));
#endif

        //kill(nPid,SIGCONT);
        printf("sleeping 10 seconds \n");
        sleep(5);
        printf("end of sleep\n");
        //ptrace(PTRACE_CONT,nPid);
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
        //kill(nPid,SIGSTOP);
        //ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp (a_argv[1], a_argv+1);
    }

	return 0;
}


//int RunCodeOnTheRemoteProc(pid_t a_pid, int a_nNumOfArgs, const void* a_pCode, )


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
