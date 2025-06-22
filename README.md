# HellsVectoredGate


HellsVectoredGate is an indirect syscall technique that combaines VEH (Vectored Exception Handler) allowing the operator to execute native system calls through exception without directly invoking the syscall instruction in a traceable way.


### Usage

Initializing NTDLL_CONFIG and NT_API structures. Finding SSN of the syscalls and random syscall instruction address:

![](/HellsVectoredGate/Media/1.png)

Memory allocation - NtAllocateVirtualMemory

![](/HellsVectoredGate/Media/2.png)

Payload writing - NtProtectVirtualMemory

![](/HellsVectoredGate/Media/3.png)

New access PAGE_EXECUTE_READ - NtWriteVirtualMemory

![](/HellsVectoredGate/Media/4.png)

New thread creation - NtCreateThreadEx

![](/HellsVectoredGate/Media/5.png)

NtWaitForSingleObject

![](/HellsVectoredGate/Media/6.png)
