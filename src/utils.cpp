/**
 * 文件名: src/utils.cpp
 * 修改: 新增 IsProcess64Bit 实现
 */

#include "utils.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <tlhelp32.h>
#include <commdlg.h>

namespace utils {

    void PrintBanner() { std::cout << "--- Injector Engine ---" << std::endl; }
    void Log(const std::string& msg, bool isError) {
        if (isError) std::cerr << "[-] " << msg << std::endl;
        else         std::cout << "[+] " << msg << std::endl;
    }

    bool EnableDebugPrivilege() {
        HANDLE hToken;
        LUID luid;
        TOKEN_PRIVILEGES tkp;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Luid = luid;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bool res = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        CloseHandle(hToken);
        return res;
    }

    std::vector<unsigned char> ReadFileToBuffer(const std::wstring& filepath) {
        FILE* file = _wfopen(filepath.c_str(), L"rb");
        if (!file) return {};
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);
        if (fileSize <= 0) { fclose(file); return {}; }
        std::vector<unsigned char> buffer(fileSize);
        size_t readSize = fread(buffer.data(), 1, fileSize, file);
        fclose(file);
        if (readSize != static_cast<size_t>(fileSize)) return {};
        return buffer;
    }

    std::vector<ProcessInfo> GetAllProcesses() {
        std::vector<ProcessInfo> list;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return list;
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID != 0) {
                    unsigned long long time = 0;
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        FILETIME ftCreate, ftExit, ftKernel, ftUser;
                        if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                            ULARGE_INTEGER ul;
                            ul.LowPart = ftCreate.dwLowDateTime;
                            ul.HighPart = ftCreate.dwHighDateTime;
                            time = ul.QuadPart;
                        }
                        CloseHandle(hProcess);
                    }
                    list.push_back({ pe32.th32ProcessID, pe32.szExeFile, time });
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        std::sort(list.begin(), list.end(), [](const ProcessInfo& a, const ProcessInfo& b){
            if (a.creationTime != 0 && b.creationTime != 0) return a.creationTime < b.creationTime;
            if (a.creationTime == 0 && b.creationTime == 0) return a.pid < b.pid;
            if (a.creationTime == 0) return true;
            if (b.creationTime == 0) return false;
            return false;
        });
        return list;
    }

    DWORD GetProcessIdByName(const std::wstring& processName) {
        auto list = GetAllProcesses();
        for (const auto& proc : list) { if (proc.name == processName) return proc.pid; }
        return 0;
    }

    std::wstring SelectFile(const wchar_t* filter) {
        OPENFILENAMEW ofn;
        wchar_t szFile[260] = { 0 };
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = filter;
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
        if (GetOpenFileNameW(&ofn) == TRUE) return std::wstring(ofn.lpstrFile);
        return L"";
    }

    // [新增] 实现 IsProcess64Bit
    bool IsProcess64Bit(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;
        BOOL isWow64 = FALSE;
        // 如果是 64 位系统：
        // 32 位进程 -> IsWow64 = TRUE
        // 64 位进程 -> IsWow64 = FALSE
        if (IsWow64Process(hProcess, &isWow64)) {
            CloseHandle(hProcess);
            return (isWow64 == FALSE);
        }
        CloseHandle(hProcess);
        return false;
    }
}