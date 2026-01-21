#include <windows.h>

// 弹窗线程函数
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    MessageBoxA(
        NULL, 
        "Success! The DLL has been injected successfully.\n\n(This is a C DLL)", // 内容
        "Injection Success", // 标题 (注意这一行末尾必须有逗号！)
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST // 按钮样式
    );
    return 0;
}

// DLL 入口函数
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // 注入时启动线程
            CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}