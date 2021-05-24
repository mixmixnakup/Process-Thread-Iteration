#include "gWin_ProcessEnumerator.h"

std::string getNtErrorCode(NTSTATUS ntStatus) {
	switch (ntStatus) {
		case STATUS_SUCCESS:
			return "NTSuccess";
		case STATUS_UNSUCCESSFUL:
			return "NTUnsuccessful";
		case STATUS_NOT_IMPLEMENTED:
			return "Not Implemented";
		case STATUS_INFO_LENGTH_MISMATCH:
			return "Length Mismatch";
		case STATUS_NO_MEMORY:
			return "No memory";
		case STATUS_ACCESS_DENIED:
			return "Access Denied";
		case STATUS_BUFFER_TOO_SMALL:
			return "Buffer too small";
		case STATUS_PROCEDURE_NOT_FOUND:
			return "Proceadure not found";
		case STATUS_NOT_SUPPORTED:
			return "Not supported";
		case STATUS_NOT_FOUND:
			return "Not found";
		case STATUS_PARTIAL_COPY:
			return "Partial copy";
		default:
			return "Unkown error";
	}
}

void PRINT_ERROR(std::string s, NTSTATUS status) {
#if PRINT_ERRORS
	std::cerr << "GetLastError() - " << GetLastError() << " - " << "NTSTATUS - " << getNtErrorCode(status) << " - " << s << std::endl;
#endif
}

namespace gWin {

void Process::enumModules() {
	gWin::SafeHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPALL, (DWORD)m_spi->UniqueProcessId);
	MODULEENTRY32 modEntry = { 0 };

	modEntry.dwSize = sizeof(MODULEENTRY32);
	m_modules.clear();

	if (!Module32First(hSnapshot.getRaw(), &modEntry))
		PRINT_ERROR("Unable to iterate through modules", 0);

	do {
		m_modules.push_back(modEntry);
	} while (Module32Next(hSnapshot.getRaw(), &modEntry));
}

void Process::enumThreads() {
	for (ULONG i = 0; i < m_spi->NumberOfThreads; ++i) {
		m_spi->Threads[i].StartAddress = (PVOID)getThreadStartAddress(m_spi->Threads[i].ClientId.UniqueThread);
		m_threads.push_back(Thread(&m_spi->Threads[i]));
	}
}

DWORD Process::getThreadStartAddress(HANDLE hThread) {
	HMODULE ntDll = GetModuleHandle("ntdll.dll");

	if (ntDll == NULL) {
		PRINT_ERROR("Unable to get module handle from ntdll.dll", 0);
		return 0;
	}

	tNtQueryInformationThread NtQueryInformationThread =
		(tNtQueryInformationThread)GetProcAddress(ntDll, ("NtQueryInformationThread"));

	if (NtQueryInformationThread == NULL) {
		PRINT_ERROR("NtQueryInformationThread was not found", 0);
		return 0;
	}

	gWin::SafeHandle hNewThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)hThread);

	DWORD threadStartAddr = 0;
	NTSTATUS retval = NtQueryInformationThread(hNewThread.getRaw(), ThreadQuerySetWin32StartAddress, &threadStartAddr, sizeof(DWORD), NULL);

	if (!NT_SUCCESS(retval)) {
		PRINT_ERROR("Unable to get start address of thread", retval);
		return 0;
	}

	return threadStartAddr;
}

ModuleInfo Process::getAssociatedModule(Thread *thread) {
	if (m_modules.size() <= 0)
		enumModules();

	for (auto &module : m_modules) {
		if (thread->getStartAddress() >= (DWORD)module.modBaseAddr &&
			thread->getStartAddress() <= ((DWORD)module.modBaseAddr + module.modBaseSize)) {
			return ModuleInfo { (DWORD)module.modBaseAddr, module.modBaseSize, module.szExePath };
		}
	}

	return ModuleInfo { 0 };
}

void ProcessEnumerator::iterateProcesses() {
	HMODULE ntDll = GetModuleHandle("ntdll.dll");

	if (ntDll == NULL)
		PRINT_ERROR("Unable to get module handle from ntdll.dll", 0);

	tNtQuerySystemInformation NtQuerySystemInformation =
		(tNtQuerySystemInformation)GetProcAddress(ntDll, ("NtQuerySystemInformation"));

	if (NtQuerySystemInformation == NULL)
		PRINT_ERROR("NtQuerySystemInformation was not found", 0);

	void *buffer = new void *[1024 * 1024];
	PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)buffer;

	NTSTATUS ntStatus = NtQuerySystemInformation(SystemProcessInformation, pSpi, 1024 * 1024, NULL);

	if (!NT_SUCCESS(ntStatus)) {
		PRINT_ERROR("Unable to iterate through process list", ntStatus);
		return;
	}

	m_processes.clear();

	while (pSpi->NextEntryOffset) {
		m_processes.push_back(Process(pSpi, buffer));

		ULONG nextEntry = (ULONG)pSpi + pSpi->NextEntryOffset;
		pSpi = (PSYSTEM_PROCESS_INFORMATION)(nextEntry);
	}
}

}