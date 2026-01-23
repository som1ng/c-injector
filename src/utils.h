/**
 * 文件名: src/utils.h
 * 修改: 新增 IsProcess64Bit 声明
 */

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
    
    // 读取文件到内存
    std::vector<unsigned char> ReadFileToBuffer(const std::wstring& filepath);

    std::vector<ProcessInfo> GetAllProcesses();
    DWORD GetProcessIdByName(const std::wstring& processName);
    std::wstring SelectFile(const wchar_t* filter);

    // [新增] 检查目标进程是否为 64 位
    bool IsProcess64Bit(DWORD pid);
}