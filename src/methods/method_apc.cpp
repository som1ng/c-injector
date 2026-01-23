/**
 * 文件名: src/methods/method_apc.cpp
 * 作用: 实现 QueueUserAPC 注入逻辑
 * 兼容性: 完美支持 x86 和 x64 (依赖编译时的架构)
 */

#include "injector_methods.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>

namespace methods {

    // 获取目标进程的所有线程 ID
    // 尽管名字带 32，但在 64 位编译下它能正确获取 64 位线程快照
    std::vector<DWORD> GetAllThreadIds(DWORD targetPid) {
        std::vector<DWORD> threads;
        
        // [API] CreateToolhelp32Snapshot: 创建指定进程、堆、模块和线程的快照
        // 参数 TH32CS_SNAPTHREAD: 表示我们在快照中包含系统中的所有线程
        // 参数 0: 对于 SNAPTHREAD 标志，进程 ID 参数被忽略（即获取全系统线程）
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return threads;

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        // [API] Thread32First: 检索快照中遇到的第一个线程的信息
        if (Thread32First(hSnapshot, &te32)) {
            do {
                // 校验结构体大小，防止版本不匹配
                if (te32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te32.th32OwnerProcessID)) {
                    // 筛选：只记录属于目标进程(targetPid)的线程
                    if (te32.th32OwnerProcessID == targetPid) {
                        threads.push_back(te32.th32ThreadID);
                    }
                }
                // [API] Thread32Next: 检索快照中记录的下一个线程的信息，用于循环遍历
            } while (Thread32Next(hSnapshot, &te32));
        }

        // [API] CloseHandle: 用完句柄必须关闭，防止资源泄露
        CloseHandle(hSnapshot);
        return threads;
    }

    // APC - DLL 注入
    bool Inject_APC_DLL(DWORD pid, const std::wstring& dllPath) {

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;
        // 1. 写入 DLL 路径
        size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        
        // [API] VirtualAllocEx: 在指定进程的虚拟地址空间中分配内存
        // 参数 NULL: 让系统决定地址
        // 参数 pathSize: 分配多大
        // 参数 MEM_COMMIT: 提交物理内存
        // 参数 PAGE_READWRITE: 内存保护属性，只需读写即可（存放字符串）
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
        if (!pRemoteMem) { CloseHandle(hProcess); return false; }

        // [API] WriteProcessMemory: 将数据写入指定进程的内存区域
        // 参数 pRemoteMem: 目标地址
        // 参数 dllPath.c_str(): 源数据（本地 DLL 路径字符串）
        if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, NULL)) {
            // [API] VirtualFreeEx: 如果写入失败，释放刚才申请的远程内存
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 2. 获取 LoadLibraryW 地址
        // [API] GetModuleHandleW: 获取 kernel32.dll 的模块句柄（它常驻内存）
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        // [API] GetProcAddress: 获取 LoadLibraryW 函数的地址
        // 注意：因为系统 DLL 在所有进程中的基址通常相同，所以我们可以直接用本地获取的地址
        PAPCFUNC pLoadLibrary = (PAPCFUNC)GetProcAddress(hKernel32, "LoadLibraryW");

        // 3. 遍历线程并插入 APC
        auto threads = GetAllThreadIds(pid);
        int successCount = 0;
        
        for (DWORD tid : threads) {
            // [API] OpenThread: 打开线程句柄
            // 参数 THREAD_SET_CONTEXT: 这是 APC 注入的关键权限！必须拥有此权限才能修改线程上下文/插入 APC
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
            if (hThread) {
                // [API] QueueUserAPC: 核心函数，往线程的 APC 队列插入任务
                // 参数 pLoadLibrary: 目标线程要执行的函数地址
                // 参数 hThread: 目标线程句柄
                // 参数 (ULONG_PTR)pRemoteMem: 传给函数的参数（这里是 DLL 路径的地址）
                if (QueueUserAPC(pLoadLibrary, hThread, (ULONG_PTR)pRemoteMem)) {
                    successCount++;
                }
                CloseHandle(hThread);
            }
        }

        CloseHandle(hProcess);
        return successCount > 0;
    }

    // APC - Shellcode 注入
    bool Inject_APC_Shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
        if (shellcode.empty()) return false;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;

        // 1. 写入 Shellcode
        // [API] VirtualAllocEx
        // 参数 PAGE_EXECUTE_READWRITE: 关键区别！因为存的是机器码，必须赋予“执行”权限，否则触发 DEP 崩溃
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteMem) { CloseHandle(hProcess); return false; }

        // [API] WriteProcessMemory
        if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode.data(), shellcode.size(), NULL)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 2. 这里的入口地址就是 Shellcode 在内存中的地址
        PAPCFUNC pShellcodeEntry = (PAPCFUNC)pRemoteMem;

        auto threads = GetAllThreadIds(pid);
        int successCount = 0;

        for (DWORD tid : threads) {
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
            if (hThread) {
                // [API] QueueUserAPC
                // 参数 pShellcodeEntry: 直接把 Shellcode 首地址作为函数执行
                // 参数 0: Shellcode 通常是自包含的，不需要参数，传 0 即可
                if (QueueUserAPC(pShellcodeEntry, hThread, 0)) {
                    successCount++;
                }
                CloseHandle(hThread);
            }
        }

        CloseHandle(hProcess);
        return successCount > 0;
    }
}