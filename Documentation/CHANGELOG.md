# 变更日志

## [0.1.0] - 2026-06-17

### Added
- 项目骨架搭建
  - 完整的目录结构
  - VS2022 解决方案和项目配置
  - VS Code 编译和调试配置
- 插件化架构接口
  - IParser 解析器接口定义
  - IAnalyzer 分析器接口定义
  - 解析器注册机制
  - 分析器管理器
- 文件映射引擎 (CFileMapper)
  - Windows 内存映射文件 API
  - 只读映射支持
  - RAII 资源管理
  - 完整错误处理
- DOS 头解析器 (CDosHeaderParser)
  - MZ 魔数验证
  - e_lfanew 提取与验证
  - 越界检查
- NT 头解析器 (CNtHeadersParser)
  - PE 签名验证
  - FileHeader 解析
  - OptionalHeader 解析 (PE32/PE32+)
- 核心控制类 (CPEAnalyzer)
  - 加载、解析、分析完整流程
  - 解析器注册机制
  - JSON/Markdown 导出
- 日志系统 (Logger)
  - 多级别日志 (Debug/Info/Warning/Error/Fatal)
  - 彩色控制台输出
  - 格式化日志宏
- 错误码系统 (ErrorCodes)
  - 分类错误码
  - 中文错误描述
  - 错误码名称
- 基础类型定义 (Types)
  - PE 相关结构体
  - 枚举定义
  - 类型别名
- 完整的项目文档
  - 项目总览
  - 架构设计
  - 插件化接口设计
  - 项目状态快照

### Changed
- N/A

### Fixed
- N/A
