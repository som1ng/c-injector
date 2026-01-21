#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace utils {
    struct ProcessInfo {
        DWORD pid;
        std::wstring name;
        unsigned long long creationTime;
    };

    void PrintBanner();
    void Log(const std::string& msg, bool isError = false);
    bool EnableDebugPrivilege();
    
    // [新增] 读取文件到内存 (Shellcode/DLL)
    std::vector<unsigned char> ReadFileToBuffer(const std::wstring& filepath);

    std::vector<ProcessInfo> GetAllProcesses();
    DWORD GetProcessIdByName(const std::wstring& processName);
    std::wstring SelectFile(const wchar_t* filter);
}