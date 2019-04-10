// These macrodefinitions are copied from linux sources
// Linux is written in C, so the definitions looked a bit
// different there.
// We could have just looked up their values and use
// them directly in right places
// However it would have made the code much less legible

#include <sys/syscall.h>

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */

#define MAP_PRIVATE	0x02		/* Changes are private.  */
#  define MAP_ANONYMOUS	0x20		/* Don't use a file.  */


//#define ARGUMENT_REG    rbx
#define ARGUMENT_REG    rdi

.data
initialBreak:
.long 0

.text
    .align 16
.global bar
    bar:
        add $1000, %rdi
        mov %rdi, %rax
        //ret
        int $3 // software interrupt

.global bar_new
    bar_new:
    //void* pNewMem = mmap(NEWNULLPTR, 100, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    // void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);

        pushq %rsi
        pushq %rdi
        pushq %rdx
        pushq %rbx
        pushq %rcx
        pushq %r8
        pushq %r9
        pushq %r10

        //movq %rdi, %rsi                           // arg. 2 ===============> size
        movq $4096, %rsi                           // arg. 2 ===============> size
        //mov $__NR_mmap, %rax                      // sys call number
        mov $9, %rax                      // sys call number
        mov $0, %rdi                              // arg. 1 ===============> addr
        mov $0, %rbx                              // arg. 1
        //mov $(PROT_READ|PROT_WRITE), %rdx         // arg. 3
        mov $PROT_READ, %rdx         // arg. 3
        mov $MAP_PRIVATE, %r10    // arg. 4 ===============> map is not shared
        //mov $(MAP_PRIVATE|MAP_ANONYMOUS), %rcx    // arg. 4
        mov $(-1), %r8                            // arg. 5 ===============> fd
        mov $0, %r9                               // arg. 6

        int $0x80                                 // syscall

        popq %r10
        popq %r9
        popq %r8
        popq %rcx
        popq %rbx
        popq %rdx
        popq %rdi
        popq %rsi

        ret


.global new_allocator
    .type  new_allocator,@function
new_allocator:
    pushq %ARGUMENT_REG
    pushq %rdi
    movq $__NR_brk, %rax
    movq $0, %ARGUMENT_REG
    int $0x80

    // save initial break
    movq %rax, %ARGUMENT_REG
    popq %rdi
    addq %rdi, %ARGUMENT_REG
    movq $__NR_brk, %rax
    int $0x80
    popq %ARGUMENT_REG
    // take out initial break
    //subq %r11, %rax
    //movq 0x100, %rax
    //int $3 // software interrupt
    popq %ARGUMENT_REG
    popq %r12
    popq %r11
    ret // this will net be executed
.global after_new_allocator
    .type  after_new_allocator,@function
after_new_allocator:
    int $3 // software interrupt
.Lfe2:
    .size new_allocator,.Lfe2-new_allocator


//
//mov r8, rax           ; rax holds opened file descriptor
//                      ; it is the fourth argument of mmap
//mov rax, 9            ; mmap number
//mov rdi, 0            ; operating system will choose mapping destination
//mov rsi, 4096         ; page size
//mov rdx, PROT_READ    ; new memory region will be marked read only
//mov r10, MAP_PRIVATE  ; pages will not be shared
//
//mov r9, 0             ; offset inside test.txt
//syscall               ; now rax will point to mapped location
//
//mov rdi, rax
//call print_string
//
//mov rax, 60           ; use exit system call to shut down correctly
//xor rdi, rdi
//syscall
