#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace methods {
    // 1. CreateRemoteThread (已在 method_crt.cpp 实现)
    bool Inject_CRT_DLL(DWORD pid, const std::wstring& dllPath);
    bool Inject_CRT_Shellcode(DWORD pid, const std::vector<unsigned char>& shellcode);

    // 2. APC (等待你实现)
    inline bool Inject_APC_DLL(DWORD pid, const std::wstring& dllPath) { (void)pid; (void)dllPath; return false; }
    inline bool Inject_APC_Shellcode(DWORD pid, const std::vector<unsigned char>& code) { (void)pid; (void)code; return false; }

    // 3. Hook (等待你实现)
    inline bool Inject_Hook_DLL(DWORD pid, const std::wstring& dllPath) { (void)pid; (void)dllPath; return false; }

    // 4. Reflective (等待你实现)
    inline bool Inject_Reflective(DWORD pid, const std::vector<unsigned char>& code) { (void)pid; (void)code; return false; }
}