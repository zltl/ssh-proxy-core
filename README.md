# SSH Proxy Core

高性能、可扩展的 SSH 协议代理服务器核心库，纯 C 语言实现。

## 特性

- **代理转发**: 透明代理和显式代理，支持多后端路由
- **过滤器链**: Envoy 风格的可扩展过滤器架构
  - Auth Filter: 用户认证 (Password, PublicKey)
  - RBAC Filter: 基于角色的访问控制
  - Audit Filter: 会话审计和录像 (asciicast 格式)
  - Rate Limit Filter: 连接速率和并发限制
- **会话管理**: 完整的 SSH 会话生命周期管理
- **路由与负载均衡**: 支持 Round-Robin、Random、最少连接、Hash 策略
- **健康检查**: 自动检测后端服务器健康状态

## 架构

```
┌─────────────┐     ┌─────────────────────────────────────┐     ┌──────────────┐
│   Client    │────▶│           SSH Proxy Core            │────▶│   Upstream   │
└─────────────┘     │  ┌─────────────────────────────┐    │     └──────────────┘
                    │  │       Filter Chain          │    │
                    │  │ ┌────────┬────────┬───────┐ │    │
                    │  │ │  Auth  │  RBAC  │ Audit │ │    │
                    │  │ └────────┴────────┴───────┘ │    │
                    │  └─────────────────────────────┘    │
                    │  ┌────────────┐  ┌──────────────┐   │
                    │  │  Session   │  │    Router    │   │
                    │  │  Manager   │  │ (Load Balancer)│ │
                    │  └────────────┘  └──────────────┘   │
                    └─────────────────────────────────────┘
```

## 项目结构

```
ssh-proxy-core/
├── src/              # 源文件 (.c)
│   ├── main.c            # 主入口
│   ├── ssh_server.c      # SSH 服务器
│   ├── session.c         # 会话管理器
│   ├── filter.c          # 过滤器链
│   ├── router.c          # 路由器
│   ├── config.c          # 配置文件加载
│   ├── auth_filter.c     # 认证过滤器
│   ├── rbac_filter.c     # RBAC 过滤器
│   ├── audit_filter.c    # 审计过滤器
│   └── rate_limit_filter.c # 速率限制
├── include/          # 头文件 (.h)
├── tests/            # 测试文件 (.c)
├── lib/              # 第三方库
├── docs/             # 文档
│   ├── DESIGN.md         # 设计文档
│   └── config.example.ini # 配置文件示例
├── scripts/          # 构建和工具脚本
├── build/            # 构建输出目录
├── Makefile          # 构建配置
└── README.md         # 本文件
```

## 构建

### 依赖

- GCC (支持 C11)
- Make
- libssh (>= 0.9.0) - SSH 协议库
- pthread - 线程支持
- crypt - 密码哈希
- (可选) clang-format - 代码格式化
- (可选) cppcheck - 静态分析

### 安装依赖 (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libssh-dev
```

### 从源码安装 libssh

如果系统包管理器中没有 libssh 或版本过旧，可以从源码安装：

```bash
./scripts/install-libssh.sh
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

### 配置文件

SSH Proxy Core 支持通过 INI 格式的配置文件管理用户认证和路由映射。

配置文件示例见 `docs/config.example.ini`。

#### 配置文件格式

```ini
# 服务器配置
[server]
bind_addr = 0.0.0.0
port = 2222
host_key = /etc/ssh-proxy/host_key

# 日志配置
[logging]
level = info
audit_dir = /var/log/ssh-proxy/audit

# 连接限制
[limits]
max_sessions = 1000
session_timeout = 3600
auth_timeout = 60

# 用户配置 (用户名在冒号后)
[user:admin]
password_hash = $6$saltsalt$...  # 使用 openssl passwd -6 生成
pubkey = ssh-rsa AAAA... admin@example.com
enabled = true

# 用户到上游服务器的路由映射
# 格式: [route:proxy_user_pattern]  支持 glob 模式 (*, ?)
[route:admin]
upstream = prod.example.com
port = 22
user = root                      # 上游服务器的用户名
privkey = /etc/ssh-proxy/keys/admin.key

[route:dev-*]
upstream = dev.example.com
user = developer
privkey = /etc/ssh-proxy/keys/dev.key

# 默认路由 (catch-all)
[route:*]
upstream = bastion.example.com
user = guest
```

#### 编程方式使用配置

```c
#include "config.h"

// 从文件加载配置
proxy_config_t *config = config_load("/etc/ssh-proxy/config.ini");

// 查找用户认证信息
config_user_t *user = config_find_user(config, "admin");
if (user != NULL) {
    // 使用 user->password_hash 或 user->pubkeys 进行认证
}

// 查找用户路由 (用于确定上游服务器和认证方式)
config_route_t *route = config_find_route(config, "dev-alice");
if (route != NULL) {
    // route->upstream_host  - 上游服务器地址
    // route->upstream_port  - 上游服务器端口
    // route->upstream_user  - 上游服务器用户名
    // route->privkey_path   - 连接上游的私钥路径
}

// 重载配置
config_reload(config, "/etc/ssh-proxy/config.ini");

// 清理
config_destroy(config);
```

## 使用

### 运行代理服务器

```bash
# 运行 (默认端口 2222)
./build/bin/ssh-proxy-core

# 指定端口
./build/bin/ssh-proxy-core -p 2223

# 调试模式
./build/bin/ssh-proxy-core -d

# 指定主机密钥
./build/bin/ssh-proxy-core -k /path/to/host_key

# 查看帮助
./build/bin/ssh-proxy-core --help
```

### 嵌入式使用

```c
#include "session.h"
#include "filter.h"
#include "router.h"

// 创建会话管理器
session_manager_config_t sm_cfg = {
    .max_sessions = 1000,
    .session_timeout = 3600,
    .auth_timeout = 60
};
session_manager_t *session_mgr = session_manager_create(&sm_cfg);

// 创建过滤器链
filter_chain_t *filters = filter_chain_create();

// 添加认证过滤器
auth_filter_config_t auth_cfg = {
    .backend = AUTH_BACKEND_CALLBACK,
    .allow_password = true,
    .password_cb = my_auth_callback,
    .cb_user_data = my_context
};
filter_chain_add(filters, auth_filter_create(&auth_cfg));

// 创建路由器
router_config_t router_cfg = {
    .lb_policy = LB_POLICY_ROUND_ROBIN,
    .connect_timeout_ms = 10000
};
router_t *router = router_create(&router_cfg);

// 添加上游服务器
upstream_config_t upstream = { .port = 22, .enabled = true };
strcpy(upstream.host, "backend.example.com");
router_add_upstream(router, &upstream);
```

## API 参考

### 会话管理器 (session.h)

```c
session_manager_t *session_manager_create(const session_manager_config_t *config);
void session_manager_destroy(session_manager_t *manager);
session_t *session_manager_create_session(session_manager_t *manager, ssh_session client);
void session_manager_remove_session(session_manager_t *manager, session_t *session);
size_t session_manager_cleanup(session_manager_t *manager);
```

### 过滤器链 (filter.h)

```c
filter_chain_t *filter_chain_create(void);
void filter_chain_destroy(filter_chain_t *chain);
int filter_chain_add(filter_chain_t *chain, filter_t *filter);
filter_status_t filter_chain_on_connect(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t filter_chain_on_auth(filter_chain_t *chain, filter_context_t *ctx);
```

### 路由器 (router.h)

```c
router_t *router_create(const router_config_t *config);
void router_destroy(router_t *router);
int router_add_upstream(router_t *router, const upstream_config_t *config);
int router_resolve(router_t *router, const char *username, const char *target, route_result_t *result);
ssh_session router_connect(router_t *router, route_result_t *result, uint32_t timeout_ms);
```

## 开发

### 添加自定义过滤器

```c
// 定义回调函数
static filter_status_t my_on_connect(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: new connection");
    return FILTER_CONTINUE;  // 或 FILTER_REJECT
}

// 创建过滤器
filter_callbacks_t callbacks = {
    .on_connect = my_on_connect,
    .on_auth = my_on_auth,
    .on_close = my_on_close
};
filter_t *my_filter = filter_create("my_filter", FILTER_TYPE_CUSTOM, &callbacks, config);

// 添加到链
filter_chain_add(chain, my_filter);
```

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

MIT License
