#include <stdio.h>
#include <windows.h>

int main() {
    // 获取当前进程 ID
    DWORD pid = GetCurrentProcessId();
    // 设置控制台标题
    SetConsoleTitleA("C Target App");
    printf("========================================\n");
    printf("   C TARGET APPLICATION (DEMO)\n");
    printf("========================================\n");
    printf("PID: [ %lu ]\n", pid);
    printf("Status: Running... Waiting for injection.\n");
    printf("Instructions:\n");
    printf("1. Keep this window open.\n");
    printf("2. Run your Rust Injector.\n");
    printf("3. Select PID %lu and inject 'hack.dll'.\n", pid);
    printf("========================================\n");

    // 无限循环，保持程序运行，每秒打印一个点
    int count = 0;
    while(1) {
        Sleep(1000); // 暂停 1 秒
        printf(".");
        count++;
        if (count % 30 == 0) {
            printf("\nStill alive (PID: %lu)...\n", pid);
        }
    }

    return 0;
}