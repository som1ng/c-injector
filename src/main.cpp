/**
 * 文件名: src/main_gui.cpp
 * 作用: GUI 主程序
 * 修改: 
 * 1. 增加了 ComboBox 用于选择注入方法
 * 2. 增加了 Edit 控件用于手动输入/显示路径
 * 3. 完善了注入方法的分发逻辑
 * 4. [新] 增加了动态提示标签，明确告知用户需要输入文件路径及格式要求
 * 5. [新] 支持直接在输入框内输入 16 进制机器码 (如 90 90 CC)
 */

#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cwctype> // for iswxdigit
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

// 全局变量
HWND hListProcess, hEditFile, hRadioDll, hRadioBin, hComboMethod, hLabelTip;
std::vector<utils::ProcessInfo> g_ProcessList;

// 注入方法列表
const wchar_t* INJECTION_METHODS[] = {
    L"1. CreateRemoteThread (经典)",
    L"2. QueueUserAPC (隐蔽)",
    L"3. SetWindowsHookEx (钩子)",
    L"4. Reflective Injection (反射式)",
    L"5. DLL Hijacking (劫持)"
};

// 辅助：解析 16 进制字符串 (如 "90 90 CC" -> {0x90, 0x90, 0xCC})
std::vector<unsigned char> ParseHexInput(const std::wstring& input) {
    std::vector<unsigned char> bytes;
    std::wstring hexStr;
    
    // 清洗输入：只保留 0-9, a-f, A-F，过滤掉空格、逗号、0x 等
    for (size_t i = 0; i < input.length(); ++i) {
        wchar_t c = input[i];
        // 跳过 "0x"
        if (c == L'0' && i + 1 < input.length() && (input[i+1] == L'x' || input[i+1] == L'X')) {
            i++; continue;
        }
        if (iswxdigit(c)) {
            hexStr += c;
        }
    }

    // 长度必须是偶数
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

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        // 左侧进程列表
        hListProcess = CreateWindow(L"LISTBOX", NULL, 
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | LBS_NOTIFY,
            20, 20, 300, 400, hwnd, (HMENU)IDC_PROCESS_LIST, NULL, NULL);

        // 右侧控件
        CreateWindow(L"BUTTON", L"刷新列表", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            340, 20, 120, 30, hwnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);

        // 注入模式 (DLL vs Shellcode)
        CreateWindow(L"STATIC", L"注入模式:", WS_CHILD | WS_VISIBLE, 340, 60, 100, 20, hwnd, NULL, NULL, NULL);
        hRadioDll = CreateWindow(L"BUTTON", L"DLL 模式", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            340, 85, 100, 20, hwnd, (HMENU)IDC_RADIO_DLL, NULL, NULL);
        hRadioBin = CreateWindow(L"BUTTON", L"Shellcode", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            450, 85, 100, 20, hwnd, (HMENU)IDC_RADIO_BIN, NULL, NULL);
        SendMessage(hRadioDll, BM_SETCHECK, BST_CHECKED, 0);

        // 注入方法 (ComboBox)
        CreateWindow(L"STATIC", L"注入方法:", WS_CHILD | WS_VISIBLE, 340, 115, 100, 20, hwnd, NULL, NULL, NULL);
        hComboMethod = CreateWindow(L"COMBOBOX", NULL, 
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            340, 140, 220, 200, hwnd, (HMENU)IDC_COMBO_METHOD, NULL, NULL);
        // 填充下拉框
        for (const auto& method : INJECTION_METHODS) {
            SendMessage(hComboMethod, CB_ADDSTRING, 0, (LPARAM)method);
        }
        SendMessage(hComboMethod, CB_SETCURSEL, 0, 0); // 默认选第1个

        // 文件选择
        CreateWindow(L"BUTTON", L"选择文件...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            340, 180, 100, 30, hwnd, (HMENU)IDC_BTN_SELECT_FILE, NULL, NULL);
        
        // 文件路径输入框 (Edit Control)
        hEditFile = CreateWindow(L"EDIT", L"", 
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            340, 220, 220, 25, hwnd, (HMENU)IDC_EDIT_FILE, NULL, NULL);
        
        // [新] 动态提示标签
        hLabelTip = CreateWindow(L"STATIC", L"提示: 请选择目标 .dll 文件路径", 
            WS_CHILD | WS_VISIBLE,
            340, 250, 230, 20, hwnd, (HMENU)IDC_STATIC_TIP, NULL, NULL);

        // 注入按钮
        CreateWindow(L"BUTTON", L"开始注入", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            340, 280, 220, 50, hwnd, (HMENU)IDC_BTN_INJECT, NULL, NULL);

        utils::EnableDebugPrivilege();
        RefreshProcessList();
        break;

    case WM_COMMAND:
        // 监听单选框点击，更新提示文字
        if (LOWORD(wParam) == IDC_RADIO_DLL) {
            SetWindowText(hLabelTip, L"提示: 请选择目标 .dll 文件路径");
        }
        else if (LOWORD(wParam) == IDC_RADIO_BIN) {
            // [新] 更新提示，告诉用户可以直接输入 Hex
            SetWindowText(hLabelTip, L"提示: 选文件 或 输入Hex (如 90 90 CC)");
        }
        else if (LOWORD(wParam) == IDC_BTN_REFRESH) {
            RefreshProcessList();
        }
        else if (LOWORD(wParam) == IDC_BTN_SELECT_FILE) {
            bool isDll = (SendMessage(hRadioDll, BM_GETCHECK, 0, 0) == BST_CHECKED);
            std::wstring file = utils::SelectFile(isDll ? L"DLL\0*.dll\0All\0*.*\0" : L"Bin\0*.bin\0All\0*.*\0");
            if (!file.empty()) {
                SetWindowText(hEditFile, file.c_str());
            }
        }
        else if (LOWORD(wParam) == IDC_BTN_INJECT) {
            int index = SendMessage(hListProcess, LB_GETCURSEL, 0, 0);
            if (index == LB_ERR) { MessageBox(hwnd, L"请先在左侧选择一个进程！", L"错误", MB_OK); break; }
            
            // 获取输入框内容 (可能是路径，也可能是 Hex)
            wchar_t pathBuf[4096]; // 稍微大一点，以防输入长 Shellcode
            GetWindowText(hEditFile, pathBuf, 4096);
            std::wstring inputStr = pathBuf;

            if (inputStr.empty()) { MessageBox(hwnd, L"请输入内容！", L"错误", MB_OK); break; }

            DWORD pid = g_ProcessList[index].pid;
            bool isDll = (SendMessage(hRadioDll, BM_GETCHECK, 0, 0) == BST_CHECKED);
            int methodIdx = SendMessage(hComboMethod, CB_GETCURSEL, 0, 0);

            bool result = false;

            if (isDll) {
                // DLL 模式只支持文件路径
                result = methods::Inject_CRT_DLL(pid, inputStr);
            } else { // Shellcode 模式
                std::vector<unsigned char> rawData;
                
                // [新] 智能判断：先检查是否为存在的 .bin 文件
                DWORD attr = GetFileAttributesW(inputStr.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    // 是文件，读取它
                    rawData = utils::ReadFileToBuffer(inputStr);
                } else {
                    // 不是文件，尝试解析为 Hex 字符串
                    rawData = ParseHexInput(inputStr);
                }

                if (rawData.empty()) { 
                    MessageBox(hwnd, L"无效输入！\n\n1. 如果是文件，请确认路径正确。\n2. 如果是代码，请确保是有效的16进制 (如 AA BB CC)。", L"错误", MB_OK); 
                    break; 
                }

                // 只有 rawData 有数据才继续
                switch (methodIdx) {
                    case 0: result = methods::Inject_CRT_Shellcode(pid, rawData); break;
                    case 1: result = methods::Inject_APC_Shellcode(pid, rawData); break;
                    case 3: result = methods::Inject_Reflective(pid, rawData); break;
                    default: MessageBox(hwnd, L"该方法不支持 Shellcode 模式", L"错误", MB_OK); break;
                }
            }

            if (result) MessageBox(hwnd, L"注入指令已发送！", L"成功", MB_ICONINFORMATION);
            else MessageBox(hwnd, L"注入失败！请检查权限或杀软设置。", L"失败", MB_ICONERROR);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"InjectorWindowClass";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"C++ Super Injector", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 600, 500, NULL, NULL, hInstance, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow);
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}