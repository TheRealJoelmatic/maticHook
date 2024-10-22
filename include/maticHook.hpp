#pragma once
#ifndef MATIC_HOOK
#define MATIC_HOOK

#include <Windows.h>
#include <vector>
#include <cstdio>
#include <cstdarg>

#define INT3 0xCC

extern "C" NTSTATUS MyNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
);

namespace maticHook {
	// Logging function
	inline void Log(const char* format, ...) {
		char buffer[256];
		va_list args;
		va_start(args, format);
		vsnprintf_s(buffer, sizeof(buffer), format, args);
		va_end(args);
		// was only logging everthing when I was testing hooks
		//std::cout << "[LOG] -> " << buffer << std::endl;
	}

	inline bool IsValidAddress(uintptr_t address)
	{
		if (address < 0x10000 || address > 0x7FFFFFFFFFFF)
		{
			return false;
		}

		return true;
	}

	inline UCHAR original_call[]{
		0x51,                                                       // push rcx
		0x52,                                                       // push rdx
		0x41, 0x50,                                                 // push r8
		0x41, 0x51,                                                 // push r9
		0x50,                                                       // push rax
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // mov rcx, function
		0x00, 0x00,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // mov rax, inthook::ignore
		0x00, 0x00,
		0xFF, 0xD0,                                                 // call rax
		0x58,                                                       // pop rax
		0x41, 0x59,                                                 // pop r9
		0x41, 0x58,                                                 // pop r8
		0x5A,                                                       // pop rdx
		0x59,                                                       // pop rcx
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // mov rax, function
		0x00, 0x00,
		0xFF, 0xE0                                                  // jmp rax
	};

	struct info {
		PVOID function;
		PVOID hook;
		PVOID original;
		UCHAR old_byte;
		DWORD old_protect;
		BOOL ignore;
		BOOL disabled;
	};
	inline std::vector<info> hooks{};
	inline PVOID seh;

	inline LONG NTAPI vectored_handler(_EXCEPTION_POINTERS* exception) {
		DWORD ex_code = exception->ExceptionRecord->ExceptionCode;
		if (ex_code != EXCEPTION_BREAKPOINT && ex_code != EXCEPTION_SINGLE_STEP)
			return EXCEPTION_CONTINUE_SEARCH;

		Log("Exception code: 0x%X at address %p", ex_code, exception->ExceptionRecord->ExceptionAddress);

		for (info& cur : hooks) {
			if (cur.disabled)
				continue;

			if (ex_code == EXCEPTION_BREAKPOINT && exception->ExceptionRecord->ExceptionAddress == cur.function) {
				Log("Breakpoint at hooked function %p", cur.function);
				if (cur.ignore) {
					*(UCHAR*)cur.function = cur.old_byte; // set original byte
					exception->ContextRecord->EFlags |= 0x100; // single step execution
					Log("Setting single-step flag");
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				exception->ContextRecord->Rip = (DWORD64)cur.hook;
				Log("Redirecting execution to hook function %p", cur.hook);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (ex_code == EXCEPTION_SINGLE_STEP && cur.ignore) {
				Log("Single-step after ignore at function %p", cur.function);
				exception->ContextRecord->EFlags &= ~0x100; // clear single-step flag
				*(UCHAR*)cur.function = INT3; // set INT3 byte
				cur.ignore = false;
				return EXCEPTION_CONTINUE_EXECUTION;
			}

		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	inline bool ignore(void* function) {
		for (info& cur : hooks) {
			if (function != cur.function || cur.disabled)
				continue;
			cur.ignore = true;
			Log("Set ignore flag for function %p", function);
			return true;
		}
		Log("Function %p not found in hooks", function);
		return false;
	}

	inline void* original(void* function) {
		void* address = VirtualAlloc(0, sizeof(original_call), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!address) {
			Log("Failed to allocate memory for original function, error: %d", GetLastError());
			return 0;
		}
		Log("Allocated memory at %p for original function", address);

		memcpy(address, &original_call, sizeof(original_call));
		Log("Copied original_call to %p", address);

#ifdef _WIN64
		* (DWORD64*)((DWORD64)address + 9) = (DWORD64)function;
		*(DWORD64*)((DWORD64)address + 19) = (DWORD64)maticHook::ignore;
		*(DWORD64*)((DWORD64)address + 38) = (DWORD64)function;
#elif _WIN32
		* (DWORD*)((DWORD)address + 1) = (DWORD)function;
		*(DWORD*)((DWORD)address + 6) = (DWORD)inthook::ignore;
		*(DWORD*)((DWORD)address + 14) = (DWORD)function;
#endif
		Log("Set function pointers in trampoline code");

		return address;
	}

	inline bool create(void* function, void* hook, void*& original) {
		info new_hook = { function, hook };
		SIZE_T regionSize = 1;
		PVOID baseAddress = function;

		if (!IsValidAddress((uintptr_t)function)) return false;

		NTSTATUS status = MyNtProtectVirtualMemory(
			GetCurrentProcess(),
			&baseAddress,
			&regionSize,
			PAGE_EXECUTE_READWRITE,
			&new_hook.old_protect
		);

		Log("Changed memory protection at %p to PAGE_EXECUTE_READWRITE", new_hook.function);

		new_hook.old_byte = *(UCHAR*)new_hook.function;
		if (IsBadWritePtr(new_hook.function, 1)) {
			Log("Cannot write to memory at %p", new_hook.function);
			return false;
		}
		*(UCHAR*)new_hook.function = INT3; // set INT3 byte
		Log("Set INT3 at function %p, old byte was 0x%02X", new_hook.function, new_hook.old_byte);

		new_hook.original = maticHook::original(new_hook.function);
		if (!new_hook.original) {
			Log("Failed to create original function trampoline");
			return false;
		}
		original = new_hook.original;
		Log("Created original function trampoline at %p", new_hook.original);

		hooks.push_back(new_hook);
		Log("Hook created for function %p", new_hook.function);

		return true;
	}

	inline bool remove(void* function) {
		DWORD unused;
		for (info& cur : hooks) {
			if (function != cur.function || cur.disabled)
				continue;
			*(UCHAR*)cur.function = cur.old_byte; // set original byte
			Log("Restored original byte at %p", cur.function);

			SIZE_T regionSize = 1;
			NTSTATUS status = MyNtProtectVirtualMemory(
				GetCurrentProcess(),
				&cur.function,
				&regionSize,
				PAGE_EXECUTE_READWRITE,
				&unused
			);

			Log("Restored memory protection at %p", cur.function);
			if (!VirtualFree(cur.original, 0, MEM_RELEASE)) {
				Log("Failed to free memory at %p, error: %d", cur.original, GetLastError());
				return false;
			}
			Log("Freed memory at %p", cur.original);
			cur.disabled = true;
			return true;
		}
		Log("Function %p not found in hooks", function);
		return false;
	}

	inline bool init() {
		seh = AddVectoredExceptionHandler(1, vectored_handler);
		if (!seh) {
			Log("Failed to add vectored exception handler, error: %d", GetLastError());
			return false;
		}
		Log("Added vectored exception handler at %p", seh);
		return true;
	}

	inline bool uninit() {
		DWORD unused;
		for (info& cur : hooks) {
			if (cur.disabled)
				continue;
			*(UCHAR*)cur.function = cur.old_byte; // set original byte

			Log("Restored original byte at %p", cur.function);

			SIZE_T regionSize = 1;
			NTSTATUS status = MyNtProtectVirtualMemory(
				GetCurrentProcess(),
				&cur.function,
				&regionSize,
				PAGE_EXECUTE_READWRITE,
				&unused
			);

			if (!VirtualFree(cur.original, 0, MEM_RELEASE)) {
				Log("Failed to free memory at %p, error: %d", cur.original, GetLastError());
			}
			else {
				Log("Freed memory at %p", cur.original);
			}
			cur.disabled = true;
		}
		hooks.clear();
		if (!RemoveVectoredExceptionHandler(seh)) {
			Log("Failed to remove vectored exception handler, error: %d", GetLastError());
			return false;
		}
		Log("Removed vectored exception handler");
		return true;
	}
}

#endif  // MATIC_HOOK