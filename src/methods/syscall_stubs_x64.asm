# syscall_stubs_x64.asm
# x64 syscall stubs - GNU Assembler (AT&T syntax)
# 编译: as --64 -o syscall_stubs_x64.o syscall_stubs_x64.asm

.text
.globl sys_alloc_wrapper
sys_alloc_wrapper:
    pushq %rbp
    movq %rsp, %rbp
    subq $32, %rsp

    movq %rcx, -8(%rbp)
    movq %rdx, -16(%rbp)
    movq %r8, -24(%rbp)

    movq -16(%rbp), %rcx
    movq -24(%rbp), %rdx
    movq %r9, %r8
    movq 16(%rbp), %r9

    movq 24(%rbp), %rax
    movq %rax, -32(%rbp)
    movq 32(%rbp), %rax
    movq %rax, -40(%rbp)

    movq %rcx, %r10
    movl %ecx, %eax
    syscall

    movq %rax, -48(%rbp)
    movq %rbp, %rsp
    popq %rbp
    ret

# ----
.globl sys_write_wrapper
sys_write_wrapper:
    pushq %rbp
    movq %rsp, %rbp
    subq $32, %rsp

    movq %rcx, -8(%rbp)
    movq %rdx, -16(%rbp)
    movq %r8, -24(%rbp)

    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 16(%rbp), %r9

    movq 24(%rbp), %rax
    movq %rax, -32(%rbp)

    movq %rcx, %r10
    movl %ecx, %eax
    syscall

    movq %rax, -40(%rbp)
    movq %rbp, %rsp
    popq %rbp
    ret

# ----
.globl sys_create_thread_wrapper
sys_create_thread_wrapper:
    pushq %rbp
    movq %rsp, %rbp
    subq $96, %rsp

    movq %rcx, -8(%rbp)
    movq %rdx, -16(%rbp)
    movq %r8, -24(%rbp)
    movq %r9, -32(%rbp)

    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 16(%rbp), %r9

    movq 24(%rbp), %rax
    movq %rax, -40(%rbp)
    movq 32(%rbp), %rax
    movq %rax, -48(%rbp)
    movq 40(%rbp), %rax
    movq %rax, -56(%rbp)
    movq 48(%rbp), %rax
    movq %rax, -64(%rbp)
    movq 56(%rbp), %rax
    movq %rax, -72(%rbp)
    movq 64(%rbp), %rax
    movq %rax, -80(%rbp)
    movq 72(%rbp), %rax
    movq %rax, -88(%rbp)

    movq -16(%rbp), %r10
    movl %ecx, %eax
    syscall

    movq %rax, -96(%rbp)
    movq %rbp, %rsp
    popq %rbp
    ret