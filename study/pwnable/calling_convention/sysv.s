	.file	"sysv.c"
	.intel_syntax noprefix
	.text
	.globl	callee
	.type	callee, @function
callee:
	endbr64
	push	rbp
	mov	rbp, rsp
	mov	QWORD PTR [rbp-24], rdi
	mov	DWORD PTR [rbp-28], esi
	mov	DWORD PTR [rbp-32], edx
	mov	DWORD PTR [rbp-36], ecx
	mov	DWORD PTR [rbp-40], r8d
	mov	DWORD PTR [rbp-44], r9d
	mov	eax, DWORD PTR [rbp-28]
	movsx	rdx, eax
	mov	rax, QWORD PTR [rbp-24]
	add	rdx, rax
	mov	eax, DWORD PTR [rbp-32]
	cdqe
	add	rdx, rax
	mov	eax, DWORD PTR [rbp-36]
	cdqe
	add	rdx, rax
	mov	eax, DWORD PTR [rbp-40]
	cdqe
	add	rdx, rax
	mov	eax, DWORD PTR [rbp-44]
	cdqe
	add	rdx, rax
	mov	eax, DWORD PTR [rbp+16]
	cdqe
	add	rax, rdx
	mov	QWORD PTR [rbp-8], rax
	mov	rax, QWORD PTR [rbp-8]
	pop	rbp
	ret
	.size	callee, .-callee
	.globl	caller
	.type	caller, @function
caller:
	endbr64
	push	rbp
	mov	rbp, rsp
	push	7
	mov	r9d, 6
	mov	r8d, 5
	mov	ecx, 4
	mov	edx, 3
	mov	esi, 2
	movabs	rax, 123456789123456789
	mov	rdi, rax
	call	callee
	add	rsp, 8
	nop
	leave
	ret
	.size	caller, .-caller
	.globl	main
	.type	main, @function
main:
	endbr64
	push	rbp
	mov	rbp, rsp
	mov	eax, 0
	call	caller
	mov	eax, 0
	pop	rbp
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
