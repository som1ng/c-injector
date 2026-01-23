#### 编译 64 位 DLL ( 64 位注入器)
```bash
g++ 1.cpp -shared -o 1.dll 
```

#### 编译 32 位 DLL ( 32 位注入器)
```bash
g++ 1.cpp -m32 -shared -o 1.dll
```
