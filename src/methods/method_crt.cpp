//支持 DLL & Shellcode
/**
 * 文件名: src/methods/method_crt.cpp
 * 作用: 实现 CreateRemoteThread 注入逻辑
 */

#include "injector_methods.h"
#include <iostream>

namespace methods {

    // ---------------------------------------------------------
    // DLL 注入逻辑
    // ---------------------------------------------------------
    bool Inject_CRT_DLL(DWORD pid, const std::wstring& dllPath) {
        // 1. 打开目标进程
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[-] OpenProcess 失败! Error: " << GetLastError() << std::endl;
            return false;
        }

        // 2. 在目标进程分配内存 (存 DLL 路径字符串)
        // 路径长度要包含结尾的空字符 (\0)，所以要 +1，宽字符要 *2
        size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
        
        if (!pRemoteMem) {
            std::cerr << "[-] VirtualAllocEx 失败!" << std::endl;
            CloseHandle(hProcess);
            return false;
        }

        // 3. 写入 DLL 路径
        if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
            std::cerr << "[-] WriteProcessMemory 失败!" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 4. 获取 LoadLibraryW 的地址 (kernel32.dll 在所有进程里的基址通常是一样的)
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

        // 5. 创建远程线程，执行 LoadLibraryW(dllPath)
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteMem, 0, NULL);
        
        if (!hThread) {
            std::cerr << "[-] CreateRemoteThread 失败! 可能是权限不足或被杀软拦截。" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 等待线程结束 (可选)
        WaitForSingleObject(hThread, 2000);

        // 清理
        CloseHandle(hThread);
        // 注意：这里不能立刻 Free 内存，因为 LoadLibrary 可能还没执行完。
        // 规范做法是等线程彻底结束后再 Free，或者干脆让它泄露这一点点内存（几十字节），防止崩溃。
        CloseHandle(hProcess);
        
        return true;
    }

    // ---------------------------------------------------------
    // Shellcode 注入逻辑
    // ---------------------------------------------------------
    bool Inject_CRT_Shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
        if (shellcode.empty()) return false;

        // 1. 打开进程
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;

        // 2. 分配内存 (注意：必须是 PAGE_EXECUTE_READWRITE，否则会崩溃)
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteMem) {
            CloseHandle(hProcess);
            return false;
        }

        // 3. 写入 Shellcode
        if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode.data(), shellcode.size(), NULL)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 4. 创建远程线程，直接从 Shellcode 起始位置开始执行
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMem, NULL, 0, NULL);
        
        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
}