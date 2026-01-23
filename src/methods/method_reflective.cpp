/**
 * 文件名: src/methods/method_reflective.cpp
 * 作用: 实现反射式 DLL 注入
 * 注意: 
 * 1. 目标 DLL 必须导出一个名为 "ReflectiveLoader" 的函数。
 * 2. 这里包含了简化的 PE 解析逻辑，用于在原始数据中查找导出函数偏移。
 */

#include "injector_methods.h"
#include <windows.h>
#include <iostream>
#include <vector>

namespace methods {

    // =============================================================
    // PE 解析辅助函数
    // =============================================================

    // 将 RVA (相对虚拟地址) 转换为文件偏移 (File Offset)
    // 因为我们是在处理原始文件数据，而不是加载后的内存镜像，所以需要转换
    DWORD Rva2Offset(DWORD rva, PIMAGE_NT_HEADERS pNtHeaders, std::vector<unsigned char>& data) {
        PIMAGE_SECTION_HEADER pSeh = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress + pSeh->Misc.VirtualSize) {
                return rva - pSeh->VirtualAddress + pSeh->PointerToRawData;
            }
            pSeh++;
        }
        return 0;
    }

    // 在原始 DLL 数据中查找导出函数 "ReflectiveLoader" 的偏移量
    DWORD GetReflectiveLoaderOffset(std::vector<unsigned char>& data) {
        // 1. 检查 DOS 头
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)data.data();
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        // 2. 检查 NT 头
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(data.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

        // 3. 获取导出表 RVA
        IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) return 0;

        // 4. 转换导出表地址
        DWORD exportOffset = Rva2Offset(exportDir.VirtualAddress, pNt, data);
        if (exportOffset == 0) return 0;

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(data.data() + exportOffset);

        // 5. 获取名称表、序号表、函数表
        DWORD* pNames = (DWORD*)(data.data() + Rva2Offset(pExport->AddressOfNames, pNt, data));
        WORD* pOrdinals = (WORD*)(data.data() + Rva2Offset(pExport->AddressOfNameOrdinals, pNt, data));
        DWORD* pFunctions = (DWORD*)(data.data() + Rva2Offset(pExport->AddressOfFunctions, pNt, data));

        // 6. 遍历导出函数名，寻找 "ReflectiveLoader"
        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            char* name = (char*)(data.data() + Rva2Offset(pNames[i], pNt, data));
            if (strcmp(name, "ReflectiveLoader") == 0) {
                // 找到了！获取它的 RVA
                DWORD loaderRva = pFunctions[pOrdinals[i]];
                // 计算它在文件中的偏移
                return Rva2Offset(loaderRva, pNt, data);
            }
        }

        return 0; // 没找到
    }

    // =============================================================
    // 注入实现
    // =============================================================
    bool Inject_Reflective(DWORD pid, const std::vector<unsigned char>& rawDllData) {
        if (rawDllData.empty()) return false;

        // 1. 在本地解析 DLL，找到 ReflectiveLoader 的偏移
        // 注意：我们必须操作 rawDllData 的副本或者引用，因为它现在还是一堆字节
        std::vector<unsigned char> buffer = rawDllData; 
        DWORD offset = GetReflectiveLoaderOffset(buffer);

        if (offset == 0) {
            std::cerr << "[-] 在 DLL 中未找到导出函数 'ReflectiveLoader'。" << std::endl;
            MessageBoxW(NULL, L"注入失败：\n目标 DLL 不是反射式 DLL。\n它必须导出 'ReflectiveLoader' 函数。", L"错误", MB_ICONERROR);
            return false;
        }

        std::cout << "[+] 找到 ReflectiveLoader 偏移: 0x" << std::hex << offset << std::dec << std::endl;

        // 2. 打开目标进程
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[-] OpenProcess 失败。" << std::endl;
            return false;
        }

        // 3. 分配内存 (RWX)
        // 我们把整个 DLL 文件作为原始数据写入，而不是映射
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, buffer.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteMem) {
            std::cerr << "[-] VirtualAllocEx 失败。" << std::endl;
            CloseHandle(hProcess);
            return false;
        }

        // 4. 写入整个 DLL 文件内容
        if (!WriteProcessMemory(hProcess, pRemoteMem, buffer.data(), buffer.size(), NULL)) {
            std::cerr << "[-] WriteProcessMemory 失败。" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 5. 计算远程线程的入口地址
        // 入口 = 分配的基址 + ReflectiveLoader 的偏移
        LPTHREAD_START_ROUTINE pEntry = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pRemoteMem + offset);

        std::cout << "[*] 正在创建远程线程，入口地址: " << pEntry << std::endl;

        // 6. 执行！
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pEntry, NULL, 0, NULL);
        if (!hThread) {
            std::cerr << "[-] CreateRemoteThread 失败。" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 7. 成功
        // 注意：我们不能释放 pRemoteMem，因为 DLL 正在里面运行。
        // 反射式加载器通常会把自己复制到新的内存区域，但这取决于 DLL 的具体实现。
        // 简单起见，我们这里就不 Free 了。
        
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
}