#include <winsock2.h>
#include <windows.h>
#include "ReflectiveLoader.h" // [关键] 包含开源的加载器头文件

// 注意：你不在这里实现 ReflectiveLoader，它的实现在 ReflectiveLoader.c 里。
// 只要把那个 .c 文件加入项目一起编译，链接器会自动把它链接进来。

extern "C" void* _ReturnAddress(void) {
    return __builtin_return_address(0);
}

// 你的业务逻辑线程
DWORD WINAPI MainThread(LPVOID lpParam) {
    MessageBoxA(NULL, "Reflective Injection Success!", "Hacker", MB_OK);
    return 0;
}

// 标准的 DllMain
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // [重点] 这里是被 ReflectiveLoader 主动调用的
            // 当代码走到这里时，环境已经由 Loader 准备好了
            DisableThreadLibraryCalls(hinstDLL);
            
            // 启动你的核心业务
            CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}