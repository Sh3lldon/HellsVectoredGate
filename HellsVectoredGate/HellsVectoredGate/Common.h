#pragma once
#include <Windows.h>

// Function Hashes - CRC32B

#define NTALLOCATEVIRTUALMEMORY		0xDD9E1BA6
#define NTPROTECTVIRTUALMEMORY		0xA734E37A
#define NTWRITEVIRTUALMEMORY		0x35E9F21A
#define NTCREATETHREADEX			0x509FD251
#define NTWAITFORSINGLEOBJECT		0xE8836AEE


// Helper Macros to setup SYSCALL and Triggering VEH

// SET_SYSCALL save the SSN and random address of syscall instruction to global variables

// TRIGGER_VEH will trigger ACCESS_VIOLATION and registered VEH will handle it

#define SET_SYSCALL(NtSyscall)(SetSyscall((DWORD)NtSyscall.dwSSN, (PVOID)NtSyscall.pSyscallInstrAddr))
#define TRIGGER_VEH(...)(TriggerVEH(__VA_ARGS__))


// Init NTDLL_CONFIG, NT_API structures
BOOL FetchNtApi();