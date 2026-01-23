#include <windows.h>

// [关键修改] 导出一个空函数
// extern "C": 防止 C++ 编译器改名 (Name Mangling)
// __declspec(dllexport): 告诉编译器把这个函数写进导出表
extern "C" __declspec(dllexport) void DummyExport() {
    // 这个函数不需要做任何事。
    // 它的唯一作用是让注入器能通过 GetProcAddress 找到一个有效的内存地址，
    // 从而满足 SetWindowsHookEx 的参数要求。
}

// 弹窗线程函数
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    MessageBoxA(
        NULL, 
        "Success! The DLL has been injected successfully.\n\n(Hook/APC/RemoteThread)", 
        "Injection Success", 
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST
    );
    return 0;
}

// DLL 入口函数
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // 优化：告诉系统不要发送线程创建/销毁的通知，减少开销
            DisableThreadLibraryCalls(hinstDLL);
            
            // 注入成功后启动线程弹窗
            CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}