# c-injector
[![License](https://img.shields.io/github/license/som1ng/c-injector)](./LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/som1ng/c-injector.svg)](https://github.com/som1ng/c-injector/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/som1ng/c-injector.svg)](https://github.com/som1ng/c-injector/issues)

基于 C++ 的 Windows DLL 注入与 Shellcode 注入工具，支持多种注入技术，便于安全测试、逆向分析与自动化开发。项目包含 GUI 及丰富的注释与源代码结构，适合学习与实际运用。

## 功能简介

c-injector 主要实现多种主流进程注入方式，包括但不限于：

- **远程线程注入**（CreateRemoteThread）：经典注入技术，支持 DLL 和 Shellcode。
- **APC 注入**（QueueUserAPC）：将 DLL/Shellcode 挂载到目标进程的线程队列中执行。
- **消息钩子注入**（SetWindowsHookEx）：依赖目标进程 UI，适合特定类型注入需求。
- **反射式 DLL 注入**（Reflective DLL Injection）：无需将 DLL 文件落盘，提升隐蔽性。
- **DLL 劫持/劫持部署**（DLL Hijacking）：支持对指定可执行文件的 DLL 劫持操作。

详细注入原理分析可见：[进阶原理博客](https://www.s0m1ng.xyz/2025/10/15/REVERSE/pe%E9%80%86%E5%90%91/dll%E4%B8%93%E9%A2%98/)

## 主要特性

- 丰富的注入方式，兼容 x86/x64 架构
- 代码全中文注释，助于理解与二次开发
- 可注入 DLL 或直接输入 Shellcode
- 自带简易 GUI 界面
- DLL 劫持等高级功能预留
- 便捷的进程遍历与辅助工具函数

## 项目结构

```
c-injector/
├── src/              # 主体源码（包含各注入方法/核心逻辑）
│   ├── methods/      # 不同注入方式实现
│   ├── utils.cpp     # 工具与辅助函数
│   └── main_gui.cpp  # 界面/主逻辑
├── dll_test/         # DEMO 及测试用目标进程
```

## 安装与编译

- 环境要求：Windows（建议 Win10+）、g++, clang 或 MSVC（需支持 C++11）
- 依赖库：Windows API，无需三方库

### 编译示例

```sh
git clone https://github.com/som1ng/c-injector.git
cd c-injector
# VS 环境可直接编译 src/main_gui.cpp ，GCC 可用 Makefile（如有）
# 示例：
g++ src/main_gui.cpp src/utils.cpp src/methods/*.cpp -o c-injector.exe -lgdi32 -lshlwapi -static
```

## 使用说明

1. 运行示例目标程序（见 dll_test/demo.c）
2. 启动 c-injector.exe，选取目标进程
3. 选择注入方式（支持 DLL 文件路径或 Shellcode 直接注入）
4. 等待“注入成功”提示

### 主要命令行参数（如适用）

- `-t <pid>`      指定目标进程
- `-m <method>`   选择注入方式（CRT/APC/HOOK/REFLECTIVE/HIJACK）
- `-d <dll>`      待注入 DLL 路径
- `-s <shellcode>` 直接注入 Shellcode（16进制/文件）

（如主以 GUI 为主请略去命令行说明）

## 贡献/交流

欢迎 issue 与 PR，或联系 [作者博客](https://www.s0m1ng.xyz/) 交流。

## License

MIT License. 仅供安全学习与研究用途，禁止用于非法用途，风险自负。
