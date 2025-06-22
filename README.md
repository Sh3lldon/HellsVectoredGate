# HellsVectoredGate


HellsVectoredGate is an indirect syscall technique that combaines VEH (Vectored Exception Handler) allowing the operator to execute native system calls through exception without directly invoking the syscall instruction in a traceable way.


### Usage

Initializing NTDLL_CONFIG and NT_API structures. Finding SSN of the syscalls and random syscall instruction address:

![1](/HellsVectoredGate/Media/1.png)

Memory allocation - NtAllocateVirtualMemory

![2](/HellsVectoredGate/Media/2.png)

Payload writing - NtProtectVirtualMemory

![3](/HellsVectoredGate/Media/3.png)

New access PAGE_EXECUTE_READ - NtWriteVirtualMemory

![4](/HellsVectoredGate/Media/4.png)

New thread creation - NtCreateThreadEx

![5](/HellsVectoredGate/Media/5.png)

NtWaitForSingleObject

![6](/HellsVectoredGate/Media/6.png)
