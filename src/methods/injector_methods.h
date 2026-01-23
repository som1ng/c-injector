/**
 * 文件名: src/methods/injector_methods.h
 * 作用: 注入方法接口声明
 * 修复: 移除了所有 inline 实现，只保留声明，防止与 .cpp 文件冲突导致重定义错误
 */
#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace methods {

    // 1. CreateRemoteThread (实现在 method_crt.cpp)
    bool Inject_CRT_DLL(DWORD pid, const std::wstring& dllPath);
    bool Inject_CRT_Shellcode(DWORD pid, const std::vector<unsigned char>& shellcode);

    // 2. QueueUserAPC (实现在 method_apc.cpp)
    bool Inject_APC_DLL(DWORD pid, const std::wstring& dllPath);
    bool Inject_APC_Shellcode(DWORD pid, const std::vector<unsigned char>& code);

    // 3. SetWindowsHookEx (实现在 method_hook.cpp)
    bool Inject_Hook_DLL(DWORD pid, const std::wstring& dllPath);

    // 4. Reflective Injection (实现在 method_reflective.cpp)
    bool Inject_Reflective(DWORD pid, const std::vector<unsigned char>& code);

    // 5. DLL Hijacking (实现在 method_hijack.cpp - 如果以后要用的话)
    // 目前 main_gui.cpp 还没调用这个，暂时可以注释掉或者只声明
    bool Deploy_Hijack(const std::wstring& targetExeDir, const std::wstring& myDllPath);
}