#ifndef UNICODE
#define UNICODE
#endif 

// [新] 必须定义这个宏才能使用 QueryFullProcessImageName
#define _WIN32_WINNT 0x0600 

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cwctype> 
#include "utils.h"
#include "methods/injector_methods.h"

#pragma comment(lib, "comctl32.lib")

// 控件 ID
#define IDC_PROCESS_LIST    101
#define IDC_BTN_REFRESH     102
#define IDC_BTN_SELECT_FILE 103
#define IDC_BTN_INJECT      104
#define IDC_EDIT_FILE       105 
#define IDC_RADIO_DLL       106
#define IDC_RADIO_BIN       107
#define IDC_COMBO_METHOD    108 
#define IDC_STATIC_TIP      109 

// 方法 ID 枚举
enum MethodID {
    M_CRT = 0,
    M_APC = 1,
    M_HOOK = 2,
    M_REFLECTIVE = 3,
    M_HIJACK = 4
};

HWND hListProcess, hEditFile, hRadioDll, hRadioBin, hComboMethod, hLabelTip;
std::vector<utils::ProcessInfo> g_ProcessList;

// [新] 辅助函数：通过 PID 获取进程完整路径 (用于劫持定位目录)
std::wstring GetProcessPath(DWORD pid) {
    std::wstring path;
    // PROCESS_QUERY_LIMITED_INFORMATION 权限通常足够获取路径，且比 PROCESS_ALL_ACCESS 更容易成功
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        // 获取进程 EXE 的完整路径 (需要 Kernel32.lib，默认已链接)
        if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
            path = buffer;
        }
        CloseHandle(hProcess);
    }
    return path;
}

// 辅助：解析 Hex 字符串
std::vector<unsigned char> ParseHexInput(const std::wstring& input) {
    std::vector<unsigned char> bytes;
    std::wstring hexStr;
    for (size_t i = 0; i < input.length(); ++i) {
        wchar_t c = input[i];
        if (c == L'0' && i + 1 < input.length() && (input[i+1] == L'x' || input[i+1] == L'X')) {
            i++; continue;
        }
        if (iswxdigit(c)) hexStr += c;
    }
    if (hexStr.empty() || hexStr.length() % 2 != 0) return {};
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        wchar_t byteStr[3] = { hexStr[i], hexStr[i+1], 0 };
        unsigned long b = std::wcstoul(byteStr, nullptr, 16);
        bytes.push_back(static_cast<unsigned char>(b));
    }
    return bytes;
}

void RefreshProcessList() {
    SendMessage(hListProcess, LB_RESETCONTENT, 0, 0);
    g_ProcessList = utils::GetAllProcesses();
    for (const auto& proc : g_ProcessList) {
        std::wstring item = L"[" + std::to_wstring(proc.pid) + L"] " + proc.name;
        SendMessage(hListProcess, LB_ADDSTRING, 0, (LPARAM)item.c_str());
    }
}

// 更新下拉列表内容
void UpdateMethodCombo(bool isDll) {
    SendMessage(hComboMethod, CB_RESETCONTENT, 0, 0);

    // 添加选项并绑定真实 ID (SetItemData)
    int idx;

    // 1. CreateRemoteThread (通用)
    idx = SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"1. CreateRemoteThread (经典)");
    SendMessage(hComboMethod, CB_SETITEMDATA, idx, M_CRT);

    // 2. QueueUserAPC (通用)
    idx = SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"2. QueueUserAPC (隐蔽)");
    SendMessage(hComboMethod, CB_SETITEMDATA, idx, M_APC);

    if (isDll) {
        // 以下方法仅支持 DLL 模式
        
        // 3. Hook
        idx = SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"3. SetWindowsHookEx (钩子)");
        SendMessage(hComboMethod, CB_SETITEMDATA, idx, M_HOOK);

        // 4. Reflective (虽然是内存加载，但通常需要 DLL 结构)
        idx = SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"4. Reflective Injection (反射式)");
        SendMessage(hComboMethod, CB_SETITEMDATA, idx, M_REFLECTIVE);

        // 5. Hijack
        idx = SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"5. DLL Hijacking (劫持)");
        SendMessage(hComboMethod, CB_SETITEMDATA, idx, M_HIJACK);
    }

    // 默认选中第一个
    SendMessage(hComboMethod, CB_SETCURSEL, 0, 0);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        hListProcess = CreateWindow(L"LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | LBS_NOTIFY, 20, 20, 300, 400, hwnd, (HMENU)IDC_PROCESS_LIST, NULL, NULL);
        CreateWindow(L"BUTTON", L"刷新列表", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 340, 20, 120, 30, hwnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);
        
        CreateWindow(L"STATIC", L"注入模式:", WS_CHILD | WS_VISIBLE, 340, 60, 100, 20, hwnd, NULL, NULL, NULL);
        hRadioDll = CreateWindow(L"BUTTON", L"DLL 模式", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP, 340, 85, 100, 20, hwnd, (HMENU)IDC_RADIO_DLL, NULL, NULL);
        hRadioBin = CreateWindow(L"BUTTON", L"Shellcode", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 450, 85, 100, 20, hwnd, (HMENU)IDC_RADIO_BIN, NULL, NULL);
        SendMessage(hRadioDll, BM_SETCHECK, BST_CHECKED, 0);

        CreateWindow(L"STATIC", L"注入方法:", WS_CHILD | WS_VISIBLE, 340, 115, 100, 20, hwnd, NULL, NULL, NULL);
        hComboMethod = CreateWindow(L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 340, 140, 220, 200, hwnd, (HMENU)IDC_COMBO_METHOD, NULL, NULL);
        
        CreateWindow(L"BUTTON", L"选择文件...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 340, 180, 100, 30, hwnd, (HMENU)IDC_BTN_SELECT_FILE, NULL, NULL);
        hEditFile = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 340, 220, 220, 25, hwnd, (HMENU)IDC_EDIT_FILE, NULL, NULL);
        hLabelTip = CreateWindow(L"STATIC", L"提示: 请选择目标 .dll 文件路径", WS_CHILD | WS_VISIBLE, 340, 250, 230, 20, hwnd, (HMENU)IDC_STATIC_TIP, NULL, NULL);
        CreateWindow(L"BUTTON", L"开始注入", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 340, 280, 220, 50, hwnd, (HMENU)IDC_BTN_INJECT, NULL, NULL);

        utils::EnableDebugPrivilege();
        RefreshProcessList();
        UpdateMethodCombo(true); // 默认初始化为 DLL 列表
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_RADIO_DLL) {
            SetWindowText(hLabelTip, L"提示: 请选择目标 .dll 文件路径");
            UpdateMethodCombo(true); // 切换到 DLL 列表
        }
        else if (LOWORD(wParam) == IDC_RADIO_BIN) {
            SetWindowText(hLabelTip, L"提示: 选文件 或 输入Hex (如 90 90 CC)");
            UpdateMethodCombo(false); // 切换到 Shellcode 列表 (只有 CRT 和 APC)
        }
        else if (LOWORD(wParam) == IDC_BTN_REFRESH) {
            RefreshProcessList();
        }
        else if (LOWORD(wParam) == IDC_BTN_SELECT_FILE) {
            bool isDll = (SendMessage(hRadioDll, BM_GETCHECK, 0, 0) == BST_CHECKED);
            std::wstring file = utils::SelectFile(isDll ? L"DLL\0*.dll\0All\0*.*\0" : L"Bin\0*.bin\0All\0*.*\0");
            if (!file.empty()) SetWindowText(hEditFile, file.c_str());
        }
        else if (LOWORD(wParam) == IDC_BTN_INJECT) {
            int index = SendMessage(hListProcess, LB_GETCURSEL, 0, 0);
            if (index == LB_ERR) { MessageBox(hwnd, L"请先在左侧选择一个进程！", L"错误", MB_OK); break; }
            
            wchar_t pathBuf[4096];
            GetWindowText(hEditFile, pathBuf, 4096);
            std::wstring inputStr = pathBuf;

            if (inputStr.empty()) { MessageBox(hwnd, L"请输入内容！", L"错误", MB_OK); break; }

            DWORD pid = g_ProcessList[index].pid;
            bool isDll = (SendMessage(hRadioDll, BM_GETCHECK, 0, 0) == BST_CHECKED);
            
            // 获取选中的 Item Data (真实的方法 ID)
            int selIdx = SendMessage(hComboMethod, CB_GETCURSEL, 0, 0);
            int methodID = (int)SendMessage(hComboMethod, CB_GETITEMDATA, selIdx, 0);

            // 架构检查
            #if defined(_WIN64)
                bool amI64 = true;
            #else
                bool amI64 = false;
            #endif
            bool targetIs64 = utils::IsProcess64Bit(pid);
            if (amI64 != targetIs64) {
                std::wstring msg = L"架构不匹配！\n\n注入器: " + std::wstring(amI64 ? L"64位" : L"32位") + 
                                   L"\n目标: " + std::wstring(targetIs64 ? L"64位" : L"32位");
                MessageBox(hwnd, msg.c_str(), L"架构错误", MB_ICONERROR);
                break; 
            }

            bool result = false;
            if (isDll) {
                switch (methodID) {
                    case M_CRT: result = methods::Inject_CRT_DLL(pid, inputStr); break;
                    case M_APC: result = methods::Inject_APC_DLL(pid, inputStr); break;
                    case M_HOOK: result = methods::Inject_Hook_DLL(pid, inputStr); break;
                    case M_REFLECTIVE: 
                        {
                            auto rawData = utils::ReadFileToBuffer(inputStr);
                            if (rawData.empty()) { MessageBox(hwnd, L"读取 DLL 文件失败", L"Err", MB_OK); break; }
                            result = methods::Inject_Reflective(pid, rawData);
                        }
                        break;
                    case M_HIJACK: 
                        // [修复] 获取目标 EXE 完整路径，传给劫持部署函数
                        {
                            std::wstring targetPath = GetProcessPath(pid);
                            if (targetPath.empty()) {
                                MessageBox(hwnd, L"无法获取目标进程路径 (可能权限不足)", L"错误", MB_ICONERROR);
                                break;
                            }
                            result = methods::Deploy_Hijack(targetPath, inputStr);
                        }
                        break;
                    default: MessageBox(hwnd, L"未知方法 ID", L"Err", MB_OK); break;
                }
            } else { 
                // Shellcode 模式
                std::vector<unsigned char> rawData;
                DWORD attr = GetFileAttributesW(inputStr.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    rawData = utils::ReadFileToBuffer(inputStr);
                } else {
                    rawData = ParseHexInput(inputStr);
                }

                if (rawData.empty()) { 
                    MessageBox(hwnd, L"无效输入！请检查文件路径或Hex格式。", L"错误", MB_ICONERROR); 
                    break; 
                }

                switch (methodID) {
                    case M_CRT: result = methods::Inject_CRT_Shellcode(pid, rawData); break;
                    case M_APC: result = methods::Inject_APC_Shellcode(pid, rawData); break;
                    default: MessageBox(hwnd, L"该方法不支持 Shellcode 模式", L"错误", MB_OK); break;
                }
            }

            if (result) MessageBox(hwnd, L"注入指令已发送！", L"成功", MB_ICONINFORMATION);
            else MessageBox(hwnd, L"注入失败！", L"失败", MB_ICONERROR);
        }
        break;

    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"InjectorWindowClass";
    WNDCLASS wc = { }; wc.lpfnWndProc = WindowProc; wc.hInstance = hInstance; wc.lpszClassName = CLASS_NAME; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"C++ Super Injector", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 600, 500, NULL, NULL, hInstance, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow);
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}