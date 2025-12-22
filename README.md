# SSH Proxy Core

纯 C 语言实现的 SSH 代理核心库。

## 项目结构

```
ssh-proxy-core/
├── src/              # 源文件 (.c)
├── include/          # 头文件 (.h)
├── tests/            # 测试文件 (.c)
├── lib/              # 第三方库
├── docs/             # 文档
├── scripts/          # 构建和工具脚本
├── build/            # 构建输出目录
├── Makefile          # 构建配置
└── README.md         # 本文件
```

## 构建

### 依赖

- GCC (支持 C11)
- Make
- (可选) clang-format - 代码格式化
- (可选) cppcheck - 静态分析

### 安装依赖 (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential
```

### 构建命令

```bash
# 调试构建 (默认)
make

# 发布构建
make release

# 构建静态库
make lib

# 清理
make clean
```

### 运行测试

```bash
make test
```

## 使用

构建后运行程序：

```bash
# 运行
make run

# 或直接运行
./build/bin/ssh-proxy-core

# 查看帮助
./build/bin/ssh-proxy-core --help

# 查看版本
./build/bin/ssh-proxy-core --version
```

## 开发

### 添加新功能

1. 在 `include/ssh_proxy.h` 添加头文件声明
2. 在 `src/` 目录实现功能
3. 在 `tests/` 目录添加测试
4. 运行 `make test` 验证

### 调试

```bash
# 调试构建
make debug

# 使用 GDB
gdb ./build/bin/ssh-proxy-core
```

### 代码质量

```bash
# 格式化代码
make format

# 静态分析
make check
```

### Make 目标

| 目标 | 说明 |
|------|------|
| `all` | 构建项目 (默认) |
| `debug` | 调试构建 |
| `release` | 发布构建 |
| `lib` | 构建静态库 |
| `test` | 运行测试 |
| `run` | 构建并运行 |
| `clean` | 清理构建 |
| `install` | 安装到系统 |
| `format` | 格式化代码 |
| `check` | 静态分析 |
| `help` | 显示帮助 |

## 许可证

[在此添加许可证]
