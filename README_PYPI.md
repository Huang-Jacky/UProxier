# UProxier · 代理服务器

基于 mitmproxy 的完整代理软件解决方案，支持 HTTP/HTTPS 代理、请求拦截、规则配置和 Web 界面。

## 功能特性

- 🔄 **HTTP/HTTPS 代理**: 完整代理，支持 HTTPS 解密开关
- 🛡️ **证书管理**: 自动生成/校验/安装 mitmproxy CA 证书
- 📋 **规则引擎**: 多动作叠加、优先级、命中短路
    - mock_response / modify_headers / modify_content / redirect
    - delay_response / conditional_response
- 💾 **持久化**: 可将抓到的请求以 JSONL 持久化
- 🌐 **Web 界面**: 实时流量、点击行查看详情、搜索、清空
- 🎯 **CLI 工具**: start/init/cert/version/examples & 静默模式
- 📊 **抓包控制**: 流媒体/大文件开关、阈值与二进制保存控制
- 🔧 **配置管理**: YAML 配置 + CLI 覆盖

## 安装

```bash
pip install uproxier
```

### 依赖要求

- Python 3.8+
- OpenSSL (用于证书生成)

## 快速开始

### 1. 启动代理

```bash
uproxier start
```

首次启动会自动在用户目录生成 `~/.uproxier/` CA 证书。

### 2. 安装证书

**Web 界面下载**：打开 Web 界面右上角"扫码下载证书"，移动设备用浏览器访问下载链接安装。

**命令行安装**：

```bash
uproxier cert
# 选择安装到系统，或按提示手动安装
```

### 3. 配置代理

在浏览器/设备中配置代理设置：

- 代理地址: `<本机IP>`
- 端口: `8001`

## 使用说明

### 命令行工具

#### 主要命令

**启动代理服务器**

```bash
uproxier start \
  --host 0.0.0.0 \                # 代理服务器监听地址
  --port 8001 \                   # 代理服务器端口
  --web-port 8002 \               # Web 界面端口
  --config <path> \               # 配置文件路径
  --save ./logs/traffic.jsonl \   # 保存请求数据到文件
  --save-format jsonl \           # 保存格式
  --enable-https \                # 启用 HTTPS 解密
  --disable-https \               # 禁用 HTTPS 解密
  --silent                        # 静默模式
  --daemon                        # 后台模式启动
```

**证书管理**

```bash
uproxier cert                     # 管理证书（生成、安装、清理）
```

**服务器控制**

```bash
uproxier status                   # 查看服务器状态
uproxier stop                     # 停止后台运行的服务器
```

**规则示例管理**

```bash
uproxier examples --list          # 列出所有可用示例
uproxier examples --readme        # 显示示例说明文档
uproxier examples --show <文件名> # 显示指定示例内容
uproxier examples --copy <文件名> # 复制示例到当前目录
```

**其他命令**

```bash
uproxier --verbose                # 详细输出
uproxier --version                # 显示版本信息
uproxier --help                   # 显示帮助信息
```

## API 使用

UProxier 提供了完整的 Python API，支持阻塞和非阻塞两种启动方式。

### 快速示例

**阻塞启动**：
```python
from proxy_server import ProxyServer

proxy = ProxyServer("config.yaml")
proxy.start("0.0.0.0", 8001, 8002)  # 阻塞启动
```

**异步启动**：
```python
from proxy_server import ProxyServer

proxy = ProxyServer("config.yaml", silent=True)
proxy.start_async("0.0.0.0", 8001, 8002)  # 非阻塞启动
# 继续执行其他代码...
proxy.stop()
```

### 详细文档

完整的 API 使用指南请参考：[API_USAGE.md](https://github.com/Huang-Jacky/UProxier/blob/main/API_USAGE.md)

包含：
- 阻塞启动 vs 异步启动的使用场景
- 完整的参数说明和示例
- 进程管理和状态检查
- 错误处理和最佳实践
- 测试和自动化场景示例

## 规则配置

项目支持在 `config.yaml` 中定义规则，包含请求/响应修改、Mock、延迟等。

### 基本规则结构

```yaml
- name: 规则名称
  enabled: true
  priority: 100
  stop_after_match: false
  match:
    host: "^api\\.example\\.com$"
    path: "^/v1/data$"
    method: "GET"
  request_pipeline: []  # 请求阶段动作
  response_pipeline:    # 响应阶段动作
    - action: mock_response
      params:
        status_code: 200
        content: '{"status": "success"}'
```

### 常用动作

**请求阶段 (request_pipeline)**

- `set_header`: 设置请求头
- `remove_header`: 删除请求头
- `rewrite_url`: URL 重写
- `redirect`: 重定向请求

**响应阶段 (response_pipeline)**

- `mock_response`: 完全替换响应
- `set_status`: 设置状态码
- `set_header`: 设置响应头
- `replace_body`: 响应体替换
- `delay`: 延迟响应

### 查看示例

```bash
uproxier examples --list          # 列出所有示例
uproxier examples --readme        # 查看示例说明
uproxier examples --copy 01_set_header.yaml  # 复制示例
```

## Web 界面

访问 `http://<本机IP>:8002` 查看 Web 界面，功能包括：

- 📊 实时流量统计
- 📋 请求/响应详情
- 🔍 流量搜索
- 💾 数据导出

## 证书管理

### 自动安装

```bash
uproxier cert
# 选择 "安装证书到系统"
```

### 手动安装

⚠️ **重要提醒**：只安装证书文件，不要安装包含私钥的文件！

**证书文件位置**：`~/.uproxier/`

- `mitmproxy-ca-cert.pem` - PEM 格式证书（推荐）
- `mitmproxy-ca-cert.der` - DER 格式证书

**安装命令**：

```bash
# macOS
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.uproxier/mitmproxy-ca-cert.pem

# Windows
certutil -addstore -f ROOT ~/.uproxier/mitmproxy-ca-cert.der

# Linux
sudo cp ~/.uproxier/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

## 故障排除

### 常见问题

1. **安装后 uproxier 命令不可用**
   ```bash
   # 如果使用 pyenv，检查版本设置
   pyenv global 3.10.6  # 替换为你的 Python 版本
   
   # 确保 Python bin 目录在 PATH 中
   export PATH="$(python3 -c "import sys; print(sys.executable.replace('python3', ''))"):$PATH"
   ```

2. **证书错误**
    - 确保证书已正确安装到系统
    - 重新生成证书：`uproxier cert`

3. **端口被占用**
    - 使用不同的端口：`uproxier start --port 8003`

4. **规则不生效**
    - 检查规则配置是否正确
    - 确认规则已启用
    - 查看日志输出

5. **HTTPS 连接失败**
    - 确保证书已安装
    - 检查浏览器代理设置

## 许可证

MIT License

## 参考

- [mitmproxy](https://mitmproxy.org/)
- [GitHub 仓库](https://github.com/Huang-Jacky/UProxier)
