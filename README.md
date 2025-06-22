# HellsVectoredGate


HellsVectoredGate is a technique that combaines VEH (Vectored Exception Handler)and indirect syscalls allowing the operator to execute native system calls through exception without directly invoking the syscall instruction in a traceable way. You must make specific exceptino (this case uses ACCESS_VIOLATION) so that registered VEH handle it.


### Usage

Initializing NTDLL_CONFIG and NT_API structures. Finding SSN of the syscalls and random syscall instruction address:

![1](/Media/1.png)

#### Memory allocation - NtAllocateVirtualMemory

![2](/Media/2.png)

#### Payload writing - NtProtectVirtualMemory

![3](/Media/3.png)

#### New access PAGE_EXECUTE_READ - NtWriteVirtualMemory

![4](/Media/4.png)

#### New thread creation - NtCreateThreadEx

![5](/Media/5.png)

#### NtWaitForSingleObject

![6](/Media/6.png)
