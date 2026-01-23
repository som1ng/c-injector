/**
 * 文件名: src/methods/method_hook.cpp
 * 作用: 实现 SetWindowsHookEx 消息钩子注入
 * 注释: 包含详细的 Windows API 用法解析
 */

#include "injector_methods.h"
#include <windows.h>
#include <iostream>
#include <vector>

namespace methods {

    // =============================================================
    // 辅助结构与函数: 寻找目标进程的 UI 线程
    // =============================================================
    struct FindWindowData {
        DWORD pid;
        DWORD threadId;
    };

    // EnumWindows 的回调函数 (系统每找到一个窗口就会调一次这个函数)
    BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        FindWindowData* data = (FindWindowData*)lParam;
        DWORD processId = 0;
        
        // [API] GetWindowThreadProcessId
        // 作用：通过窗口句柄 (hwnd) 查户口。
        // 参数 1: 窗口句柄。
        // 参数 2 (&processId): [输出] 把这个窗口属于哪个进程 PID 写到这个变量里。
        // 返回值: 这个窗口是由哪个线程 (Thread ID) 创建的。
        DWORD threadId = GetWindowThreadProcessId(hwnd, &processId);

        // [API] IsWindowVisible
        // 作用：判断窗口是否可见（肉眼能看到）。
        // 逻辑：我们只关心属于目标进程(data->pid)且可见的窗口。
        // 因为不可见的隐藏窗口通常不处理消息，注入进去也没法触发。
        if (processId == data->pid && IsWindowVisible(hwnd)) {
            data->threadId = threadId;
            return FALSE; // 找到了，返回 FALSE 告诉系统“不用再找了”
        }
        return TRUE; // 没找到，返回 TRUE 告诉系统“继续找下一个窗口”
    }

    // 根据 PID 获取一个 UI 线程 ID
    DWORD GetUIThreadId(DWORD pid) {
        FindWindowData data = { pid, 0 };
        
        // [API] EnumWindows
        // 作用：遍历屏幕上所有的顶层窗口。
        // 参数 1: 回调函数地址。系统每找到一个窗口，就会去执行 EnumWindowsProc。
        // 参数 2: 自定义参数。我们把 data 的地址传进去，方便回调函数把结果写回来。
        EnumWindows(EnumWindowsProc, (LPARAM)&data);
        return data.threadId;
    }

    // =============================================================
    // Hook 注入实现
    // =============================================================
    bool Inject_Hook_DLL(DWORD pid, const std::wstring& dllPath) {
        // 1. 寻找 UI 线程
        DWORD threadId = GetUIThreadId(pid);
        if (threadId == 0) {
            std::cerr << "[-] 未找到 UI 线程！Hook 注入通常需要目标有窗口。" << std::endl;
            
            // [API] MessageBoxW
            // 作用：弹出一个简单的提示框。
            // 参数 MB_ICONERROR: 显示一个红色的错误图标 X。
            MessageBoxW(NULL, L"目标进程没有可见窗口，无法使用消息钩子注入。", L"错误", MB_ICONERROR);
            return false;
        }

        // 2. 在注入器本地加载 DLL
        // [API] LoadLibraryW
        // 作用：把 DLL 文件加载到 *当前进程* (注入器) 的内存里。
        // 为什么：因为 SetWindowsHookEx 需要传一个“导出函数的内存地址”。
        // 我们必须先把它载入自己的内存，算出这个地址，然后告诉操作系统：“以后别的进程要用这个函数，就在这个相对位置找”。
        HMODULE hDll = LoadLibraryW(dllPath.c_str());
        if (!hDll) {
            std::cerr << "[-] 无法加载 DLL 文件。路径正确吗？" << std::endl;
            return false;
        }

        // 3. 获取导出函数地址 (Hook Procedure)
        // [API] GetProcAddress
        // 作用：在 DLL 的导出表里查找函数的地址。
        // 参数 (LPCSTR)1: 这里我们用了“序号查找” (Ordinal 1)。
        // 意思是：我不管你函数名叫什么，给我拿第 1 个导出的函数来。
        // (这就是为什么你的 DLL 必须加 __declspec(dllexport))
        HOOKPROC pFn = (HOOKPROC)GetProcAddress(hDll, (LPCSTR)1);
        
        if (!pFn) {
            std::cerr << "[-] DLL 没有导出函数！Hook 注入需要 DLL 至少导出一个函数。" << std::endl;
            
            // [API] FreeLibrary
            // 作用：释放 DLL，减少引用计数。如果计数为0，从内存卸载。
            // 既然失败了，就把刚才加载的 DLL 卸掉，别占茅坑不拉屎。
            FreeLibrary(hDll);
            return false;
        }

        // 4. 安装钩子 (WH_GETMESSAGE)
        // [API] SetWindowsHookExW (核心中的核心)
        // 作用：设立“安检规则”。
        // 参数 1 (WH_GETMESSAGE): 钩子类型。表示我们要拦截“消息队列里取出的消息”。
        // 参数 2 (pFn): 钩子函数地址。
        // 参数 3 (hDll): 特工所属的单位（DLL 模块句柄）。
        // 参数 4 (threadId): 目标线程 ID。指定只监听这一个线程。
        // 原理：一旦调用成功，Windows 为了让目标线程能执行 pFn，会自动把 hDll 注入到目标进程。
        HHOOK hHook = SetWindowsHookExW(WH_GETMESSAGE, pFn, hDll, threadId);
        
        if (!hHook) {
            // [API] GetLastError
            // 作用：如果上一条 API 失败了，这里返回具体的错误代码（比如 5=拒绝访问）。
            std::cerr << "[-] SetWindowsHookEx 失败! Error: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return false;
        }

        std::cout << "[+] 钩子已安装。正在触发..." << std::endl;

        // 5. 触发钩子
        // [API] PostThreadMessageW
        // 作用：往目标线程的信箱（消息队列）里塞一封信。
        // 参数 WM_NULL: 一封空信，啥内容没有。
        // 目的：目标线程可能正在睡觉。塞封信把它叫醒，它一处理信件，就会触发我们的钩子，进而加载 DLL。
        PostThreadMessageW(threadId, WM_NULL, 0, 0);

        // 6. 等待并清理
        std::cout << "[*] 等待注入生效..." << std::endl;
        
        // [API] Sleep
        // 作用：暂停 1000 毫秒 (1秒)。让子弹飞一会儿，给目标一点时间去加载 DLL。
        Sleep(1000); 

        // [API] UnhookWindowsHookEx
        // 作用：撤销“安检规则”。
        // 为什么：注入已经完成了，特工已经在屋里了。如果不撤销，每来一个消息都要检查，系统会变卡。
        UnhookWindowsHookEx(hHook);
        
        // 释放本地的 DLL
        FreeLibrary(hDll);

        std::cout << "[+] 流程结束。DLL 应该已经留在目标进程里了。" << std::endl;
        return true;
    }
}