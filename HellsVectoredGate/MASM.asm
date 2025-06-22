.data
	dSSN				DWORD	0h
	qSyscallInstrAddr	QWORD	0h


.code

	SetSyscall	PROC
		xor eax, eax					; eax = 0
		xor rbx, rbx					; rbx = 0

		mov	eax, ecx					; eax & ecx = SSN
		xchg eax, dSSN					; dSSN = SSN

		mov rbx, rdx					; rbx = rdx = random syscall instruction address
		xchg rbx, qSyscallInstrAddr		; qSyscallInstrAddr = rbx
		ret								
	SetSyscall	ENDP

	TriggerVEH	PROC
		xor r11, r11
		xor eax, eax
		xor rbx, rbx					; r11 & eax & rbx = 0

		xchg r11, qSyscallInstrAddr		; r11 = qSyscallInstrAddr | qSyscallInstrAddr = 0

		mov ebx, dSSN					; ebx  = dSSN
		mov dSSN, eax					; dSSN = 0
		jmp rbx							; Triggering ACCESS_VIOLATION exception. VEH function will be activated
		
		xor	 r11, r11
		xor rbx, rbx					; r11 & rbx = 0
		ret
	TriggerVEH	ENDP


end