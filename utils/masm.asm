.code

system_crash PROC

	xor rax, rax
	xor rcx, rcx
	xor rbx, rbx
	xor rdx, rdx
	xor rsi, rsi
	xor rdi, rdi
	xor rbp, rbp
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor r11, r11
	xor r12, r12
	xor r13, r13
	xor r14, r14
	xor r15, r15
	xor rsp, rsp
	mov rsp, 1488h
	jmp rax

system_crash ENDP

_sti PROC
	sti
	ret
_sti ENDP

_cli PROC
	cli
	ret
_cli ENDP

end