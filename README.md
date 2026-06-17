# PE Static Sentinel (PE静态安全分析器)

**PE Static Sentinel** 是一款面向 Windows PE 文件的静态安全分析工具，采用插件化架构设计，支持模块化扩展。

## 功能概览

本项目规划了五大核心功能模块：

| 模块 | 状态 | 说明 |
|------|------|------|
| PE 结构解析引擎 | ✅ 里程碑一 | DOS头、NT头、节表、导入/导出表等 |
| 静态安全分析引擎 | 🔜 未来阶段 | TLS回调、熵值、危险API、数字签名 |
| 报告生成系统 | 🔜 未来阶段 | JSON、Markdown、HTML |
| 插件化扩展框架 | 🔜 未来阶段 | 自定义解析器/分析器插件 |
| 交互式分析工具 | 🔜 未来阶段 | 十六进制查看器、树形浏览器 |

## 当前进度

**里程碑一 ✅ 已完成** (v0.1.0)

- [x] 项目骨架搭建
- [x] 插件化架构 (IParser / IAnalyzer)
- [x] 文件映射引擎 (CFileMapper)
- [x] DOS 头解析器 (CDosHeaderParser)
- [x] NT 头解析器 (CNtHeadersParser)
- [x] 核心控制类 (CPEAnalyzer)
- [x] 日志系统 / 错误码系统
- [x] 完整项目文档

## 编译方法

### VS2022 (推荐)

1. 打开 `PE_Scanner.sln`
2. 选择配置 (Debug/Release) 和平台 (x64/Win32)
3. 生成解决方案 (Ctrl+Shift+B)

### VS Code + GCC

```bash
# 使用 tasks.json 中的任务
Ctrl+Shift+B → "Build with GCC (Debug)"

# 或手动编译
g++ -g -Wall -Wextra -std=c++17 -IInclude \
    Source/Core/Logger.cpp \
    Source/Core/ErrorCodes.cpp \
    Source/Parsers/DosHeaderParser.cpp \
    Source/Parsers/NtHeadersParser.cpp \
    Source/Utils/FileMapper.cpp \
    Source/Analyzers/AnalyzerManager.cpp \
    Source/PEAnalyzer.cpp \
    Source/PE_Scanner.cpp \
    -o PE_Scanner.exe
```

### VS Code + MSVC

```bash
# 使用 tasks.json 中的任务
Ctrl+Shift+B → "Build with MSVC (Release)"
```

## 使用方法

```bash
# 基本用法
PE_Scanner.exe test.exe

# JSON 格式输出
PE_Scanner.exe -j test.exe

# Markdown 报告
PE_Scanner.exe -m test.exe

# 调试模式
PE_Scanner.exe -d test.exe

# 帮助信息
PE_Scanner.exe -h
```

### 输出示例

```
========== PE 文件分析结果 ==========
文件路径: test.exe
文件大小: 123456 字节
PE 类型: PE32

--- DOS 头 ---
e_magic: 0x5A4D (MZ)
e_lfanew: 256
状态: ✅ 有效

--- NT 头 ---
签名: PE\0\0
Machine: 0x8664 (x64)
节区数量: 5
入口点: 0x00001000
镜像基址: 0x00400000
镜像大小: 81920
校验和: 0x00000000
```

## 插件开发指南

### 添加新解析器

1. 在 `Include/Parsers/` 下创建头文件，继承 `IParser` 接口
2. 在 `Source/Parsers/` 下创建实现文件
3. 在 `wmain` 中注册：`analyzer.RegisterParser(std::make_unique<PE::CYourParser>())`

### 添加新分析器

1. 在 `Include/Analyzers/` 下创建头文件，继承 `IAnalyzer` 接口
2. 在 `Source/Analyzers/` 下创建实现文件
3. 在 `wmain` 中注册：`analyzer.RegisterAnalyzer(std::make_unique<PE::CYourAnalyzer>())`

详细说明请参考 `Documentation/Design/02_插件化接口设计.md`

## 项目结构

```
PE_Scanner/
├── Include/          # 头文件
│   ├── Core/         # 核心类型、错误码、日志
│   ├── Interfaces/   # 插件接口
│   ├── Parsers/      # 解析器声明
│   ├── Analyzers/    # 分析器声明
│   └── Utils/        # 工具类声明
├── Source/           # 源文件
│   ├── Core/         # 核心实现
│   ├── Parsers/      # 解析器实现
│   ├── Analyzers/    # 分析器实现
│   └── Utils/        # 工具类实现
├── Documentation/    # 文档
└── tests/            # 测试 (预留)
```

## 许可证

本项目仅供学习和研究使用。

---

*PE Static Sentinel - 让 PE 分析更简单、更安全*
# PE Static Sentinel (PE静态安全分析器)

**PE Static Sentinel** 是一款面向 Windows PE 文件的静态安全分析工具，采用插件化架构设计，支持模块化扩展。

## 功能概览

本项目规划了五大核心功能模块：

| 模块 | 状态 | 说明 |
|------|------|------|
| PE 结构解析引擎 | ✅ 里程碑一 | DOS头、NT头、节表、导入/导出表等 |
| 静态安全分析引擎 | 🔜 未来阶段 | TLS回调、熵值、危险API、数字签名 |
| 报告生成系统 | 🔜 未来阶段 | JSON、Markdown、HTML |
| 插件化扩展框架 | 🔜 未来阶段 | 自定义解析器/分析器插件 |
| 交互式分析工具 | 🔜 未来阶段 | 十六进制查看器、树形浏览器 |

## 当前进度

**里程碑一 ✅ 已完成** (v0.1.0)

- [x] 项目骨架搭建
- [x] 插件化架构 (IParser / IAnalyzer)
- [x] 文件映射引擎 (CFileMapper)
- [x] DOS 头解析器 (CDosHeaderParser)
- [x] NT 头解析器 (CNtHeadersParser)
- [x] 核心控制类 (CPEAnalyzer)
- [x] 日志系统 / 错误码系统
- [x] 完整项目文档

## 编译方法

### VS2022 (推荐)

1. 打开 `PE_Scanner.sln`
2. 选择配置 (Debug/Release) 和平台 (x64/Win32)
3. 生成解决方案 (Ctrl+Shift+B)

### VS Code + GCC

```bash
# 使用 tasks.json 中的任务
Ctrl+Shift+B → "Build with GCC (Debug)"

# 或手动编译
g++ -g -Wall -Wextra -std=c++17 -IInclude \
    Source/Core/Logger.cpp \
    Source/Core/ErrorCodes.cpp \
    Source/Parsers/DosHeaderParser.cpp \
    Source/Parsers/NtHeadersParser.cpp \
    Source/Utils/FileMapper.cpp \
    Source/Analyzers/AnalyzerManager.cpp \
    Source/PEAnalyzer.cpp \
    Source/PE_Scanner.cpp \
    -o PE_Scanner.exe
```

### VS Code + MSVC

```bash
# 使用 tasks.json 中的任务
Ctrl+Shift+B → "Build with MSVC (Release)"
```

## 使用方法

```bash
# 基本用法
PE_Scanner.exe test.exe

# JSON 格式输出
PE_Scanner.exe -j test.exe

# Markdown 报告
PE_Scanner.exe -m test.exe

# 调试模式
PE_Scanner.exe -d test.exe

# 帮助信息
PE_Scanner.exe -h
```

### 输出示例

```
========== PE 文件分析结果 ==========
文件路径: test.exe
文件大小: 123456 字节
PE 类型: PE32

--- DOS 头 ---
e_magic: 0x5A4D (MZ)
e_lfanew: 256
状态: ✅ 有效

--- NT 头 ---
签名: PE\0\0
Machine: 0x8664 (x64)
节区数量: 5
入口点: 0x00001000
镜像基址: 0x00400000
镜像大小: 81920
校验和: 0x00000000
```

## 插件开发指南

### 添加新解析器

1. 在 `Include/Parsers/` 下创建头文件，继承 `IParser` 接口
2. 在 `Source/Parsers/` 下创建实现文件
3. 在 `wmain` 中注册：`analyzer.RegisterParser(std::make_unique<PE::CYourParser>())`

### 添加新分析器

1. 在 `Include/Analyzers/` 下创建头文件，继承 `IAnalyzer` 接口
2. 在 `Source/Analyzers/` 下创建实现文件
3. 在 `wmain` 中注册：`analyzer.RegisterAnalyzer(std::make_unique<PE::CYourAnalyzer>())`

详细说明请参考 `Documentation/Design/02_插件化接口设计.md`

## 项目结构

```
PE_Scanner/
├── Include/          # 头文件
│   ├── Core/         # 核心类型、错误码、日志
│   ├── Interfaces/   # 插件接口
│   ├── Parsers/      # 解析器声明
│   ├── Analyzers/    # 分析器声明
│   └── Utils/        # 工具类声明
├── Source/           # 源文件
│   ├── Core/         # 核心实现
│   ├── Parsers/      # 解析器实现
│   ├── Analyzers/    # 分析器实现
│   └── Utils/        # 工具类实现
├── Documentation/    # 文档
└── tests/            # 测试 (预留)
```

## 许可证

本项目仅供学习和研究使用。

---

*PE Static Sentinel - 让 PE 分析更简单、更安全*
