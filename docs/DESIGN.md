# SSH Proxy Core - 设计文档

## 概述

SSH Proxy Core 旨在构建一个高性能、可扩展的 SSH 协议代理服务器。类似于 HTTP 领域的 Nginx、Envoy 或 OpenResty，它位于 SSH 客户端与后端 SSH 服务器之间，提供流量转发、访问控制、会话审计和协议转换等功能。

## 核心目标

1.  **代理 (Proxy)**: 支持透明代理和显式代理，能够根据策略将 SSH 连接路由到不同的后端服务器。
2.  **审计 (Audit)**: 提供细粒度的会话审计功能，包括命令记录、输入/输出流录制 (asciicast 格式) 以及元数据日志。
3.  **可扩展性**: 采用类似 Envoy 的过滤器 (Filter) 架构，允许通过插件扩展认证、鉴权、日志和协议处理逻辑。

## 架构设计

系统采用事件驱动的异步 I/O 模型，主要组件包括：

### 1. 监听器 (Listener)
负责监听 SSH 端口 (默认 2222)，接受客户端连接。支持配置多个监听器以处理不同类型的流量。

### 2. 会话管理器 (Session Manager)
管理 SSH 会话的生命周期。每个连接被抽象为一个 Session，包含 Client 端和 Upstream 端。

### 3. 过滤器链 (Filter Chain)
参考 Envoy 设计，流量经过一系列过滤器处理：
*   **Auth Filter**: 处理用户认证 (PublicKey, Password, Keyboard-Interactive)，支持对接 LDAP/OIDC/GitHub 等外部身份源。
*   **RBAC Filter**: 基于用户身份和目标主机进行访问控制。
*   **Audit Filter**: 捕获会话数据流，异步写入审计存储。
*   **Rate Limit Filter**: 限制连接速率和并发数。

### 4. 路由与负载均衡 (Router & Upstream)
*   **Router**: 根据用户名、目标地址或元数据决定连接转发的目标。
*   **Upstream**: 维护与后端服务器的连接池，支持健康检查。

## 数据流

1.  **连接建立**: Client 发起 SSH 连接 -> Listener 接收 -> 创建 Session。
2.  **认证阶段**: Auth Filter 介入，验证 Client 身份。
3.  **路由决策**: 认证通过后，Router 解析目标 Upstream。
4.  **后端连接**: Proxy 发起连接到 Upstream Server。
5.  **数据转发**: 建立双向管道 (Pipe)，在转发过程中 Audit Filter 实时捕获数据。
6.  **连接终止**: 任意一方断开，Session 销毁，审计日志归档。

## 审计功能详情

*   **命令审计**: 解析 SSH exec 请求和 shell 交互中的命令。
*   **录像审计**: 记录 TTY 输出流，支持回放。
*   **存储**: 支持本地文件、S3 或 Elasticsearch 存储审计记录。

## 类似项目对比

*   **Teleport**: 功能强大但较重，本项目侧重于轻量级核心库和灵活的嵌入式使用。
*   **OpenSSH**: 标准实现，缺乏细粒度代理和审计的可编程性。

