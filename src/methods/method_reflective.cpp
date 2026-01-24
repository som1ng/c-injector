/**
 * 文件名: src/methods/method_reflective.cpp
 * 作用: 实现反射式 DLL 注入
 * 修改: 增强了 GetReflectiveLoaderOffset 的兼容性，支持模糊匹配导出函数名
 */

#include "injector_methods.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstring> // for strstr

namespace methods {

    // 辅助：RVA 转 文件偏移
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

    // 查找导出函数偏移 (增强版)
    DWORD GetReflectiveLoaderOffset(std::vector<unsigned char>& data) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)data.data();
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(data.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

        IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) {
            std::cerr << "[-] DLL 没有导出表 (Export Table not found)" << std::endl;
            return 0;
        }

        DWORD exportOffset = Rva2Offset(exportDir.VirtualAddress, pNt, data);
        if (exportOffset == 0) return 0;

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(data.data() + exportOffset);

        DWORD* pNames = (DWORD*)(data.data() + Rva2Offset(pExport->AddressOfNames, pNt, data));
        WORD* pOrdinals = (WORD*)(data.data() + Rva2Offset(pExport->AddressOfNameOrdinals, pNt, data));
        DWORD* pFunctions = (DWORD*)(data.data() + Rva2Offset(pExport->AddressOfFunctions, pNt, data));

        std::cout << "[*] 正在扫描导出表 (" << pExport->NumberOfNames << " functions)..." << std::endl;

        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            char* name = (char*)(data.data() + Rva2Offset(pNames[i], pNt, data));
            
            // [调试信息] 打印所有发现的函数名，方便排错
            std::cout << "    Found Export: " << name << std::endl;

            // [关键修改] 使用 strstr 进行模糊匹配
            // 只要名字里包含 "ReflectiveLoader" 就认为是对的
            // 这能兼容 _ReflectiveLoader, ReflectiveLoader@4 等变体
            if (strstr(name, "ReflectiveLoader") != nullptr) {
                DWORD loaderRva = pFunctions[pOrdinals[i]];
                DWORD fileOffset = Rva2Offset(loaderRva, pNt, data);
                
                std::cout << "[+] 匹配成功! Using: " << name << " (Offset: 0x" << std::hex << fileOffset << ")" << std::dec << std::endl;
                return fileOffset;
            }
        }

        return 0;
    }

    bool Inject_Reflective(DWORD pid, const std::vector<unsigned char>& rawDllData) {
        if (rawDllData.empty()) return false;

        std::vector<unsigned char> buffer = rawDllData; 
        DWORD offset = GetReflectiveLoaderOffset(buffer);

        if (offset == 0) {
            std::cerr << "[-] 未找到 ReflectiveLoader 导出函数。" << std::endl;
            MessageBoxW(NULL, L"注入失败：\nDLL 中未找到包含 'ReflectiveLoader' 的导出函数。\n请查看控制台日志确认导出表内容。", L"错误", MB_ICONERROR);
            return false;
        }

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[-] OpenProcess 失败。" << std::endl;
            return false;
        }

        // 分配 RWX 内存
        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, buffer.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteMem) {
            CloseHandle(hProcess);
            return false;
        }

        // 写入 DLL
        if (!WriteProcessMemory(hProcess, pRemoteMem, buffer.data(), buffer.size(), NULL)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 计算入口并执行
        LPTHREAD_START_ROUTINE pEntry = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pRemoteMem + offset);
        
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pEntry, NULL, 0, NULL);
        if (!hThread) {
            std::cerr << "[-] CreateRemoteThread 失败。" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 等待线程初始化，不立即释放内存
        // 实际上在反射注入中，我们通常不释放这块原始内存，因为它包含了正在运行的代码
        WaitForSingleObject(hThread, 1000);
        
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        std::cout << "[+] 反射注入线程已创建。" << std::endl;
        return true;
    }
}