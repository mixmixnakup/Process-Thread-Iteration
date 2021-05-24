#pragma once

/*
	NT Internals Process Enumerator
	- Created by greyb1t 2016-04-22

	I'd appreciate if you left this comment here when copy pasting it somewhere else.
	Thank you!
*/

#include <iostream>
#include <Windows.h>
#include <vector>
#include <memory>
#include <string>
#include <TlHelp32.h>

#include "nt_ddk.h"

#define PRINT_ERRORS true

std::string getNtErrorCode(NTSTATUS ntStatus);
void PRINT_ERROR(std::string s, NTSTATUS status);

namespace gWin {

struct ModuleInfo {
	DWORD base;
	DWORD size; 
	std::string name;
};

class SafeHandle {
public:
	SafeHandle() {}
	// Legal Usage (constructor):
	// gWin::SafeHandle handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	SafeHandle(HANDLE handle) : m_handle(handle) {}

	~SafeHandle() {
		CloseHandle(m_handle);
	}

	SafeHandle(const SafeHandle &source) {
		this->operator=(source);
	}

	// Legal Usage (assignment operator):
	// handle1 = handle2;
	SafeHandle& operator= (const SafeHandle &hSource) {
		// TODO: Check if DuplicateHandle is the function which is needed

		m_handle = hSource.m_handle;
		return *this;
	}

	SafeHandle& operator= (const HANDLE hSource) {
		// TODO: Check if DuplicateHandle is the function which is needed
		m_handle = hSource;
		return *this;
	}

	const HANDLE getRaw() const {
		return m_handle;
	}

private:
	HANDLE m_handle;
};

class Thread {
public:
	Thread(SYSTEM_THREADS_INFORMATION *threadInfo) : m_threadInfo(threadInfo) {}
	~Thread() {}

	SYSTEM_THREADS_INFORMATION *getPtr() { return m_threadInfo; }

	// Getters
	DWORD getStartAddress() { return (DWORD)m_threadInfo->StartAddress; }
	DWORD getProcessId() { return (DWORD)m_threadInfo->ClientId.UniqueProcess; }
	DWORD getThreadId() { return (DWORD)m_threadInfo->ClientId.UniqueThread; }
	int getPriority() { return m_threadInfo->Priority; }
	ULONG getContextSwitchCount() { return m_threadInfo->ContextSwitchCount; }
	int getState() { return m_threadInfo->State; }
	KWAIT_REASON getWaitReason() { return m_threadInfo->WaitReason; }
	gWin::SafeHandle getHandle() { return OpenThread(THREAD_ALL_ACCESS, FALSE, getThreadId()); }

private:
	SYSTEM_THREADS_INFORMATION *m_threadInfo;
};

class Process {
public:
	Process(SYSTEM_PROCESS_INFORMATION *spi, PVOID buf) : m_spi(spi), m_allBuffer(buf) {}

	void deallocWholeBuffer() { delete[] m_allBuffer; }
	SYSTEM_PROCESS_INFORMATION *getPtr() { return m_spi; }

	std::vector<Thread> &getThreads() {
		if (m_threads.size() <= 0)
			enumThreads();

		return m_threads;
	}

	std::vector<MODULEENTRY32> &getModules() {
		if (m_modules.size() <= 0)
			enumModules();

		return m_modules;
	}

	std::string getName() {
		if (m_spi->ImageName.Buffer != nullptr) {
			std::wstring wProcName = m_spi->ImageName.Buffer;
			return std::string(wProcName.begin(), wProcName.end());
		}
		else {
			return "nullptr";
		}
	}

	ModuleInfo getAssociatedModule(Thread *thread);
	DWORD getId() { return (DWORD)m_spi->UniqueProcessId; }

private:
	void enumModules();
	void enumThreads();

	DWORD getThreadStartAddress(HANDLE hThread);

private:
	std::vector<Thread> m_threads;
	std::vector<MODULEENTRY32> m_modules;

	SYSTEM_PROCESS_INFORMATION *m_spi;
	_SYSTEM_HANDLE_INFORMATION_T<PVOID> *m_shi;

	PVOID m_allBuffer;
};

class ProcessEnumerator {
public:
	ProcessEnumerator() { iterateProcesses(); }
	~ProcessEnumerator() { 
		if (m_processes.size() >= 0)
			m_processes[0].deallocWholeBuffer(); 
	}

	std::vector<Process> &getProcesses() {
		return m_processes;
	}

private:
	void iterateProcesses();

private:
	std::vector<Process> m_processes;
};

}