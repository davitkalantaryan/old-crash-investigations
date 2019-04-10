#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

// number of bytes in a JMP/CALL rel32 instruction
#define REL32_SZ 5

// copy in the string including the trailing null byte
static const char *format = "instruction pointer = %p\n";

// text seen in /proc/<pid>/maps for text areas
static const char *text_area = " r-xp ";

// this should be a string that will uniquely identify libc in /proc/<pid>/maps
static const char *libc_string = "/libc-2";

// find the location of a shared library in memory
void *find_library(pid_t pid, const char *libname) {
  char filename[32];
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE *f = fopen(filename, "r");
  char *line = NULL;
  size_t line_size = 0;

  while (getline(&line, &line_size, f) >= 0) {
    char *pos = strstr(line, libname);
    if (pos != NULL && strstr(line, text_area)) {
      long val = strtol(line, NULL, 16);
      free(line);
      fclose(f);
      return (void *)val;
    }
  }
  free(line);
  fclose(f);
  return NULL;
}

// Update the text area of pid at the area starting at where. The data copied
// should be in the new_text buffer whose size is given by len. If old_text is
// not null, the original text data will be copied into it. Therefore old_text
// must have the same size as new_text.
int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len) {
  if (len % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return -1;
  }

  long poke_data;
  for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
    memmove(&poke_data, new_text + copied, sizeof(poke_data));
    if (old_text != NULL) {
      errno = 0;
      long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }
      memmove(old_text + copied, &peek_data, sizeof(peek_data));
    }
    if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
      perror("PTRACE_POKETEXT");
      return -1;
    }
  }
  return 0;
}

int do_wait(const char *name) {
  int status;
  if (wait(&status) == -1) {
    perror("wait");
    return -1;
  }
  if (WIFSTOPPED(status)) {
    if (WSTOPSIG(status) == SIGTRAP) {
      return 0;
    }
    printf("%s unexpectedly got status %s\n", name, strsignal(status));
    return -1;
  }
  printf("%s got unexpected status %d\n", name, status);
  return -1;

}

int singlestep(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    perror("PTRACE_SINGLESTEP");
    return -1;
  }
  return do_wait("PTRACE_SINGLESTEP");
}

void check_yama(void) {
  FILE *yama_file = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
  if (yama_file == NULL) {
    return;
  }
  char yama_buf[8];
  memset(yama_buf, 0, sizeof(yama_buf));
  fread(yama_buf, 1, sizeof(yama_buf), yama_file);
  if (strcmp(yama_buf, "0\n") != 0) {
    printf("\nThe likely cause of this failure is that your system has "
           "kernel.yama.ptrace_scope = %s",
           yama_buf);
    printf("If you would like to disable Yama, you can run: "
           "sudo sysctl kernel.yama.ptrace_scope=0\n");
  }
  fclose(yama_file);
}

int32_t compute_jmp(void *from, void *to) {
  int64_t delta = (int64_t)to - (int64_t)from - REL32_SZ;
  if (delta < INT_MIN || delta > INT_MAX) {
    printf("cannot do relative jump of size %li; did you compile with -fPIC?\n",
           delta);
    exit(1);
  }
  return (int32_t)delta;
}

int fprintf_process(pid_t pid) {
  // attach to the process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
    perror("PTRACE_ATTACH");
    check_yama();
    return -1;
  }

  // wait for the process to actually stop
  if (waitpid(pid, 0, WSTOPPED) == -1) {
    perror("wait");
    return -1;
  }

  // save the register state of the remote process
  struct user_regs_struct oldregs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs)) {
    perror("PTRACE_GETREGS");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
  }
  void *rip = (void *)oldregs.rip;
  printf("their %%rip           %p\n", rip);

  // First, we are going to allocate some memory for ourselves so we don't
  // need
  // to stop on the remote process' memory. We will do this by directly
  // invoking
  // the mmap(2) system call and asking for a single page.
  struct user_regs_struct newregs;
  memmove(&newregs, &oldregs, sizeof(newregs));
  newregs.rax = 9;                           // mmap
  newregs.rdi = 0;                           // addr
  newregs.rsi = PAGE_SIZE;                   // length
  newregs.rdx = PROT_READ | PROT_EXEC;       // prot
  newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
  newregs.r8 = -1;                           // fd
  newregs.r9 = 0;                            //  offset

  uint8_t old_word[8];
  uint8_t new_word[8];
  new_word[0] = 0x0f; // SYSCALL
  new_word[1] = 0x05; // SYSCALL
  new_word[2] = 0xff; // JMP %rax
  new_word[3] = 0xe0; // JMP %rax

  // insert the SYSCALL instruction into the process, and save the old word
  if (poke_text(pid, rip, new_word, old_word, sizeof(new_word))) {
    goto fail;
  }

  // set the new registers with our syscall arguments
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // invoke mmap(2)
  if (singlestep(pid)) {
    goto fail;
  }

  // read the new register state, so we can see where the mmap went
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    return -1;
  }

  // this is the address of the memory we allocated
  void *mmap_memory = (void *)newregs.rax;
  if (mmap_memory == (void *)-1) {
    printf("failed to mmap\n");
    goto fail;
  }
  printf("allocated memory at  %p\n", mmap_memory);

  printf("executing jump to mmap region\n");
  if (singlestep(pid)) {
    goto fail;
  }

  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  if (newregs.rip == (long)mmap_memory) {
    printf("successfully jumped to mmap area\n");
  } else {
    printf("unexpectedly jumped to %p\n", (void *)newregs.rip);
    goto fail;
  }

  // Calculate the position of the fprintf routine in the other process'
  // address
  // space. This is a little bit tricky because of ASLR on Linux. What we do
  // is
  // we find the offset in memory that libc has been loaded in their process,
  // and then we find the offset in memory that libc has been loaded in our
  // process. Then we take the delta betwen our fprintf and our libc start,
  // and
  // assume that the same delta will apply to the other process.
  //
  // For this mechanism to work, this program must be compiled with -fPIC to
  // ensure that our fprintf has an address relative to the one in libc.
  //
  // Additionally, this could fail if libc has been updated since the remote
  // process has been restarted. This is a pretty unlikely situation, but if
  // the
  // remote process has been running for a long time and you update libc, the
  // offset of the symbols could have changed slightly.
  void *their_libc = find_library(pid, libc_string);
  void *our_libc = find_library(getpid(), libc_string);
  void *their_fprintf = their_libc + ((void *)fprintf - our_libc);
  FILE *their_stderr = their_libc + ((void *)stderr - our_libc);
  printf("their libc           %p\n", their_libc);
  printf("their fprintf        %p\n", their_libc);
  printf("their stderr         %p\n", their_stderr);

  // We want to make a call like:
  //
  //   fprintf(stderr, "instruction pointer = %p\n", rip);
  //
  // To do this we're going to do the following:
  //
  //   * put a CALL instruction into the mmap area that calls fprintf
  //   * put a TRAP instruction right after the CALL
  //   * put the format string right after the TRAP
  //   * use the TRAP to restore the original text/program state

  // memory we are going to copy into our mmap area
  uint8_t new_text[32];
  memset(new_text, 0, sizeof(new_text));

  // insert a CALL instruction
  size_t offset = 0;
  new_text[offset++] = 0xe8; // CALL rel32
  int32_t fprintf_delta = compute_jmp(mmap_memory, their_fprintf);
  memmove(new_text + offset, &fprintf_delta, sizeof(fprintf_delta));
  offset += sizeof(fprintf_delta);

  // insert a TRAP instruction
  new_text[offset++] = 0xcc;

  // copy our fprintf format string right after the TRAP instruction
  memmove(new_text + offset, format, strlen(format));

  // update the mmap area
  printf("inserting code/data into the mmap area at %p\n", mmap_memory);
  if (poke_text(pid, mmap_memory, new_text, NULL, sizeof(new_text))) {
    goto fail;
  }

  if (poke_text(pid, rip, new_word, NULL, sizeof(new_word))) {
    goto fail;
  }

  // set up our registers with the args to fprintf
  // memmove(&newregs, &oldregs, sizeof(newregs));
  newregs.rax = 0;                          // no vector registers are used
  newregs.rdi = (long)their_stderr;         // pointer to stderr in the caller
  newregs.rsi = (long)mmap_memory + offset; // pointer to the format string
  newregs.rdx = oldregs.rip;                // the integer we want to print

  printf("setting the registers of the remote process\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // continue the program, and wait for the trap
  printf("continuing execution\n");
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  if (do_wait("PTRACE_CONT")) {
    goto fail;
  }

  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  newregs.rax = (long)rip;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  new_word[0] = 0xff; // JMP %rax
  new_word[1] = 0xe0; // JMP %rax
  poke_text(pid, (void *)newregs.rip, new_word, NULL, sizeof(new_word));

  printf("jumping back to original rip\n");
  if (singlestep(pid)) {
    goto fail;
  }
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }

  if (newregs.rip == (long)rip) {
    printf("successfully jumped back to original %%rip at %p\n", rip);
  } else {
    printf("unexpectedly jumped to %p (expected to be at %p)\n",
           (void *)newregs.rip, rip);
    goto fail;
  }

  // unmap the memory we allocated
  newregs.rax = 11;                // munmap
  newregs.rdi = (long)mmap_memory; // addr
  newregs.rsi = PAGE_SIZE;         // size
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // make the system call
  printf("making call to mmap\n");
  if (singlestep(pid)) {
    goto fail;
  }
  if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  printf("munmap returned with status %llu\n", newregs.rax);

  printf("restoring old text at %p\n", rip);
  poke_text(pid, rip, old_word, NULL, sizeof(old_word));

  printf("restoring old registers\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  // detach the process
  printf("detaching\n");
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
    goto fail;
  }
  return 0;

fail:
  poke_text(pid, rip, old_word, NULL, sizeof(old_word));
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
  }
  return 1;
}

int main(int argc, char **argv) {
    // dlopen = open + mmap
    return fprintf_process(24963);
#if 0
  long pid = -1;
  int c;
  opterr = 0;
  while ((c = getopt(argc, argv, "hp:")) != -1) {
    switch (c) {
    case 'h':
      printf("Usage: %s -p <pid>\n", argv[0]);
      return 0;
      break;
    case 'p':
      pid = strtol(optarg, NULL, 10);
      if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
          (errno != 0 && pid == 0)) {
        perror("strtol");
        return 1;
      }
      if (pid < 0) {
        fprintf(stderr, "cannot accept negative pids\n");
        return 1;
      }
      break;
    case '?':
      if (optopt == 'p') {
        fprintf(stderr, "Option -p requires an argument.\n");
      } else if (isprint(optopt)) {
        fprintf(stderr, "Unknown option `-%c`.\n", optopt);
      } else {
        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
      }
      return 1;
      break;
    default:
      abort();
    }
  }
  if (pid == -1) {
    fprintf(stderr, "must specify a remote process with -p\n");
    return 1;
  }
  return fprintf_process((pid_t)pid);
#endif
}

#if 0

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
#include <sys/mman.h>
#include <sys/syscall.h>

// https://www.i-programmer.info/programming/cc/3978-executable-code-injection-in-linux.html?start=1
// https://courses.cs.washington.edu/courses/cse378/10au/sections/Section1_recap.pdf

#ifdef __RTLD_DLOPEN
#define NEW_RTLD_DLOPEN	__RTLD_DLOPEN
#else
#define NEW_RTLD_DLOPEN	0x80000000
#endif


void ptraceWrite(int a_pid, unsigned long long a_addr, const void *a_data, size_t a_len) {
    long word = 0;
    size_t i = 0;
    const char* data = static_cast<const char*>(a_data);

    for (i=0; i < a_len; i+=sizeof(word), word=0) {
      memcpy(&word, data + i, sizeof(word));
      if (ptrace(PTRACE_POKETEXT, a_pid, a_addr + i, word) == -1) {
        printf("[!] Error writing process memory\n");
        exit(1);
      }
    }
}


void ptraceRead(int a_pid, unsigned long long a_addr, void *a_data, size_t a_len) {
    long word = 0;
    size_t i = 0;
    char* data = static_cast<char*>(a_data);

    for (i=0; i < a_len; i+=sizeof(word), word=0) {
        word=ptrace(PTRACE_PEEKTEXT, a_pid, a_addr + i, NULL);
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

extern "C" void* new_allocator(size_t);
extern "C" int bar(size_t);
extern "C" size_t bar_new(size_t);
extern "C" void* after_new_allocator(size_t);


int main(int a_argc, char* a_argv[])
{
    int nReturn = -1;
    int nPid;
    //int nValue=1;
    //int vPipes[2];

    if(a_argc<2){
        fprintf(stderr,"command to debug is not provided!\n");
        return 1;
    }

    int nBar = bar(1000);
    size_t nBar2 = bar_new(4096);
    int nBar3 = static_cast<int>(nBar2);
    //void* pNewMem = after_new_allocator(100);
    void* pNewMem = mmap(NEWNULLPTR, 100, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    // void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);
    printf("pid=%d, pNewMem=%p, bar:%d, bar2:%d, __NR_mmap=%d\n",getpid(),pNewMem,nBar,nBar3,__NR_mmap);

    //return  0;

    nPid = fork();

    if(nPid){
        const unsigned long long int constBrkPoint=0xcc;
        void* pLibcDlopenAddress;
        Elf64_Sym *pElfDlOpen=nullptr;
        Dl_info dlIndoDlOpen;
        int nDlAddrReturn;
        unsigned long long int ullnDlOpenSize, unStrLenPlus1, unStrLenRounded, unMallocSize;
        struct user_regs_struct regs0,regs;
        pid_t w;
        int status;
        enum __ptrace_setoptions options;
        unsigned long long int ullnAllocReturned;
        unsigned long long int rspInitial;
        //const char* pNewAllocator = reinterpret_cast<const char*>(&new_allocator);
        const char* pNewAllocator = reinterpret_cast<const char*>(&bar);
        const char* pNewAllocatorEnd = reinterpret_cast<const char*>(&after_new_allocator);
        ptrdiff_t unNewAllocatorSize = pNewAllocatorEnd - pNewAllocator;
        ptrdiff_t unNewAllocatorSizeRounded = (unNewAllocatorSize+7)/8*8;
        char* pcInitialRipBuffer = static_cast<char*>(alloca(unNewAllocatorSizeRounded));

        pLibcDlopenAddress = reinterpret_cast<void*>(&__libc_dlopen_mode);

        nDlAddrReturn = dladdr1(pLibcDlopenAddress,&dlIndoDlOpen,reinterpret_cast<void**>(&pElfDlOpen),RTLD_DL_SYMENT);
        if((!nDlAddrReturn)||(!pElfDlOpen)){
            goto finalWaitPoint;
        }
        ullnDlOpenSize = (pElfDlOpen->st_size+7)/8*8;
        unStrLenPlus1 = strlen(LIB_TO_OPENNAME) + 1;
        unStrLenRounded = (unStrLenPlus1+7)/8*8;
        unMallocSize = ullnDlOpenSize + unStrLenRounded;

        ptrace(PTRACE_ATTACH,nPid);
        //waitpid(nPid,&status,0);
        options = PTRACE_O_TRACEEXEC;
        ptrace(PTRACE_SETOPTIONS ,nPid,&options);
        //kill(nPid,SIGCONT);
        //s_TimeForExecv = 1;
        //write(vPipes[1],&nValue,4);
        //close(vPipes[0]);
        //close(vPipes[1]);
        ptrace(PTRACE_CONT,nPid);
        sleep(1);

        /* Here we start remote code running */
        ptrace(PTRACE_GETREGS, nPid, NULL, &regs);
        memcpy(&regs0,&regs,sizeof(regs));

        //regs.rsp -= 8;
        regs.rip += 2;

        ptraceRead(nPid,regs.rip,pcInitialRipBuffer,static_cast<size_t>(unNewAllocatorSizeRounded));
        //ptraceRead(nPid,regs.rsp,&rspInitial,sizeof(unsigned long long int));

        ptraceWrite(nPid,regs.rip,pNewAllocator,static_cast<size_t>(unNewAllocatorSizeRounded));
        //ptraceWrite(nPid,regs0.rip,&constBrkPoint,sizeof(unsigned long long int)); // this is done in the assembly
        //ptraceWrite(nPid,regs.rsp,&regs0.rip,sizeof(unsigned long long int));
        regs.rdi = unMallocSize;
        ptrace(PTRACE_SETREGS, nPid, NULL, &regs);
        ptrace(PTRACE_CONT,nPid);
        wait(&status);
        //wait(&status);
        // let's examine allocation result
        ptrace(PTRACE_GETREGS, nPid, NULL, &regs);
        ullnAllocReturned = regs.rax; // return from malloc

        printf("ullnAllocReturned:%u\n",static_cast<unsigned int>(ullnAllocReturned));
        if(!ullnAllocReturned){
            goto finalRecoveryPoint;
        }

        regs.rsp -= 8;

        ptraceRead(nPid,regs.rsp,&rspInitial,sizeof(unsigned long long int));
        ptraceWrite(nPid,ullnAllocReturned,pLibcDlopenAddress,pElfDlOpen->st_size);
        ptraceWrite(nPid,ullnAllocReturned+ullnDlOpenSize,LIB_TO_OPENNAME,unStrLenPlus1);
        ptraceWrite(nPid,regs0.rip,&constBrkPoint,sizeof(unsigned long long int));
        ptraceWrite(nPid,regs.rsp,&regs0.rip,sizeof(unsigned long long int));

        regs.rip = ullnAllocReturned;
        regs.rdi = ullnAllocReturned+ullnDlOpenSize;
        regs.rsi = RTLD_NOW | NEW_RTLD_DLOPEN;

        ptrace(PTRACE_SETREGS, nPid, NULL, &regs);
        ptrace(PTRACE_CONT,nPid);
        wait(&status);

        /* Let's recover everything */
        ptraceWrite(nPid,regs.rsp,&rspInitial,sizeof(unsigned long long int));
        nReturn = 0;
finalRecoveryPoint:
        ptraceWrite(nPid,regs0.rip,pcInitialRipBuffer,static_cast<size_t>(unNewAllocatorSizeRounded));
        ptrace(PTRACE_SETREGS, nPid, NULL, &regs0);

        ptrace(PTRACE_CONT,nPid);
        /* End of remote code running */


        //kill(nPid,SIGCONT);
        printf("sleeping 10 seconds \n");
        sleep(5);
        printf("end of sleep\n");
        //ptrace(PTRACE_CONT,nPid);
        ptrace(PTRACE_DETACH, nPid);

finalWaitPoint:
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
        } while (!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));
    }
    else{
        nReturn = 0;

#if 0
        while(!s_TimeForExecv){
            usleep(10);
        }
#endif
        //read(vPipes[0],&nValue,4);
        //close(vPipes[0]);
        //close(vPipes[1]);

        //InitializeCrashAnalizer();
        //SetMemoryInvestigator(&HookFunctionStatic);
        //kill(getpid(),SIGSTOP);
        //dlopen("/afs/ifh.de/user/k/kalantar/dev/sys/bionic/lib/libinject.so.1",RTLD_LAZY);
        //kill(nPid,SIGSTOP);
        //ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp (a_argv[1], a_argv+1);
    }

    return nReturn;
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

#endif
