# UProxier · 代理服务器

基于 mitmproxy 的完整代理软件解决方案，支持 HTTP/HTTPS 代理、请求拦截、规则配置和 Web 界面。

## 功能特性

- 🔄 **HTTP/HTTPS 代理**: 完整代理，支持 HTTPS 解密开关（配置或 CLI 覆盖）
- 🛡️ **证书管理**: 自动生成/校验/安装 mitmproxy CA 证书
- 📋 **规则引擎**: 多动作叠加、优先级、命中短路（stop_after_match）
    - mock_response（支持本地文件 file）/ modify_headers / modify_content / redirect
    - modify_response_headers / modify_response_content / modify_status
    - delay_response（真实延迟发送）/ conditional_response（条件分支）
    - 配置继承（extends）支持，相对路径自动解析
- 💾 **持久化**: 可将抓到的请求以 JSONL 持久化（--save，覆盖模式）
- 🌐 **Web 界面**: 实时流量、点击行查看详情、搜索、清空，完全离线化
- 🎯 **CLI 工具**: start/init/cert/version/examples/validate & 静默模式（--silent）
- 📊 **抓包控制**: 流媒体/大文件开关、阈值与二进制保存控制（通过 config.yaml 配置）
- 🔧 **配置管理**: 统一配置目录（~/.uproxier/），YAML 配置 + CLI 覆盖
- ✅ **配置验证**: 完整的配置验证系统，检查语法、类型、文件存在性等

## 安装

### 从 PyPI 安装（推荐）

```bash
pip install uproxier
```

### 从源码安装

```bash
git clone https://github.com/Huang-Jacky/UProxier.git
cd UProxier
pip install -r requirements.txt
```

### 依赖要求

- Python 3.8+
- OpenSSL (用于证书生成)

## 快速开始

### 从 PyPI 安装（推荐）

1. 安装 UProxier

```bash
pip install uproxier
```

2. 启动代理（首次启动会自动在用户目录生成 `~/.uproxier/certificates/` CA 证书；启动面板将显示证书路径与有效期）

```bash
uproxier start
```

3. 安装证书

```bash
uproxier cert
# 选择安装到系统，或按提示手动安装
```

### 从源码安装

1. 安装 UProxier

```bash
git clone https://github.com/Huang-Jacky/UProxier.git
cd UProxier
pip install -r requirements.txt
```

2. 启动代理（首次启动会自动在用户目录生成 `~/.uproxier/certificates/` CA 证书；启动面板将显示证书路径与有效期）

```bash
python3 -m uproxier start
```

3. 安装证书

```bash
python3 -m uproxier cert
# 选择安装到系统，或按提示手动安装
```

### 首次使用（自动生成证书）

3. 安装证书

- **Web 界面下载**：打开 Web 界面右上角"扫码下载证书"，移动设备用浏览器访问下载链接安装（下载的是 DER 格式，文件名为 `uproxier-ca.cer`）
- **命令行安装**：

```bash
# 从 PyPI 安装后
uproxier cert

# 从源码运行
python3 -m uproxier cert
# 选择安装到系统，或按提示手动安装
```

4. 在需要抓包的设备/浏览器里设置 HTTP(S) 代理为本机 IP 与启动端口

### 1. 初始化配置（可选）

首次启动会自动生成证书。若需要手动生成或安装证书，可使用：

```bash
python3 -m uproxier cert
```

### 2. 配置浏览器代理

在浏览器/设备中配置代理设置：

- 代理地址: `<本机IP>`
- 端口: `8001`

## 使用说明

### 命令行工具

#### 帮助信息

```
# 从 PyPI 安装后使用
uproxier --help
uproxier start --help      # 查看启动命令的所有参数
uproxier examples --help   # 查看示例管理命令的所有参数
uproxier cert --help       # 查看证书管理命令的所有参数
uproxier init --help       # 查看初始化命令的所有参数
uproxier info --help       # 查看版本信息命令的所有参数
uproxier validate --help   # 查看配置验证命令的所有参数

# 从源码运行
python3 -m uproxier --help
python3 -m uproxier start --help      # 查看启动命令的所有参数
python3 -m uproxier examples --help   # 查看示例管理命令的所有参数
python3 -m uproxier cert --help       # 查看证书管理命令的所有参数
python3 -m uproxier init --help       # 查看初始化命令的所有参数
python3 -m uproxier info --help       # 查看版本信息命令的所有参数
python3 -m uproxier validate --help   # 查看配置验证命令的所有参数
```

#### 全局选项

```bash
# 从 PyPI 安装后使用
uproxier --verbose          # 详细输出
uproxier --config <path>    # 指定配置文件路径
uproxier --version          # 显示版本信息

# 从源码运行
python3 -m uproxier --verbose          # 详细输出
python3 -m uproxier --config <path>    # 指定配置文件路径
python3 -m uproxier --version          # 显示版本信息
```

#### 主要命令

**启动代理服务器**

```bash
# 从 PyPI 安装后使用
uproxier start \
  --port 8001 \                   # 代理服务器端口
  --web-port 8002 \               # Web 界面端口
  --config <path> \               # 配置文件路径（可选，默认使用 ~/.uproxier/config.yaml）
  --save ./logs/traffic.jsonl \   # 保存请求数据到文件（JSONL格式）
  --enable-https \                # 启用 HTTPS 解密（覆盖配置）
  --disable-https \               # 禁用 HTTPS 解密（覆盖配置）
  --silent                        # 静默模式，不输出任何信息
  --daemon                        # 后台模式启动

# 从源码运行
python3 -m uproxier start \
  --port 8001 \                   # 代理服务器端口
  --web-port 8002 \               # Web 界面端口
  --config <path> \               # 配置文件路径（可选，默认使用 ~/.uproxier/config.yaml）
  --save ./logs/traffic.jsonl \   # 保存请求数据到文件（JSONL格式）
  --enable-https \                # 启用 HTTPS 解密（覆盖配置）
  --disable-https \               # 禁用 HTTPS 解密（覆盖配置）
  --silent                        # 静默模式，不输出任何信息
  --daemon                        # 后台模式启动
```

**证书管理**

```bash
# 从 PyPI 安装后使用
uproxier cert               # 管理证书（生成、安装、清理）

# 从源码运行
python3 -m uproxier cert               # 管理证书（生成、安装、清理）
```

**服务器控制**

```bash
# 从 PyPI 安装后使用
uproxier status             # 查看服务器状态
uproxier stop               # 停止后台运行的服务器

# 从源码运行
python3 -m uproxier status             # 查看服务器状态
python3 -m uproxier stop               # 停止后台运行的服务器
```

**初始化配置**

```bash
# 从 PyPI 安装后使用
uproxier init --config <path>                 # 指定配置文件路径

# 从源码运行
python3 -m uproxier init --config <path>                 # 指定配置文件路径
```

**版本信息**

```bash
# 从 PyPI 安装后使用
uproxier info               # 显示版本信息

# 从源码运行
python3 -m uproxier info               # 显示版本信息
```

**配置验证**

```bash
# 从 PyPI 安装后使用
uproxier validate <config_file>                    # 验证配置文件
uproxier validate <config_file> --validate-only    # 只进行验证，不生成完整报告
uproxier validate <config_file> --format json      # 输出 JSON 格式报告
uproxier validate <config_file> --output report.txt # 保存报告到文件

# 从源码运行
python3 -m uproxier validate <config_file>                    # 验证配置文件
python3 -m uproxier validate <config_file> --validate-only    # 只进行验证，不生成完整报告
python3 -m uproxier validate <config_file> --format json      # 输出 JSON 格式报告
python3 -m uproxier validate <config_file> --output report.txt # 保存报告到文件
```

**规则示例管理**

```bash
# 从 PyPI 安装后使用
uproxier examples --list                    # 列出所有可用示例
uproxier examples --readme                  # 显示示例说明文档
uproxier examples --show <文件名>           # 显示指定示例内容
uproxier examples --copy <文件名>           # 复制示例到当前目录

# 从源码运行
python3 -m uproxier examples --list                    # 列出所有可用示例
python3 -m uproxier examples --readme                  # 显示示例说明文档
python3 -m uproxier examples --show <文件名>           # 显示指定示例内容
python3 -m uproxier examples --copy <文件名>           # 复制示例到当前目录
```

## API 使用

UProxier 提供了完整的 Python API，支持阻塞和非阻塞两种启动方式。

### 快速示例

**阻塞启动**：
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml")
proxy.start(8001, 8002)  # 阻塞启动，监听 0.0.0.0:8001
```

**异步启动**：
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml", silent=True)
proxy.start_async(8001, 8002)  # 非阻塞启动，监听 0.0.0.0:8001
# 继续执行其他代码...
proxy.stop()
```

**保存请求数据**：
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml", save_path="requests.jsonl")
proxy.start(8001, 8002)  # 同时保存请求数据到文件
```

### 详细文档

完整的 API 使用指南请参考：[API_USAGE.md](API_USAGE.md)

包含：
- 阻塞启动 vs 异步启动的使用场景
- 完整的参数说明和示例
- 进程管理和状态检查
- 错误处理和最佳实践
- 测试和自动化场景示例

### 抓包配置

基础抓包默认开启；流媒体/大文件/二进制内容保存默认关闭。可直接编辑 `config.yaml` 中的 `capture` 段进行控制：

```yaml
# 抓包配置
capture:
  # 是否启用流媒体抓包（默认关闭，避免性能开销）
  enable_streaming: false
  # 是否启用大文件抓包（默认关闭）
  enable_large_files: false
  # 大文件阈值（字节）
  large_file_threshold: 1048576  # 1MB
  # 是否保存二进制内容（默认关闭）
  save_binary_content: false
  # 是否启用 HTTPS 解密（默认启用，可被 CLI 参数覆盖）
  enable_https: true

```

#### 抓取过滤（include / exclude）

支持在 `capture` 下按“白名单/黑名单”过滤是否将请求写入 UI 与持久化：

```yaml
capture:
  include:
    hosts: [ "^api\\.example\\.com$", "^rule\\.detailroi\\.com$" ]
    paths: [ "^/v1/", "^/rule/" ]
    methods: [ "GET", "POST" ]
  exclude:
    hosts: [ "^static\\.", "^ads\\.", "^metrics\\." ]
    paths: [ "^/favicon\\.ico$", "^/assets/" ]
    methods: [ "OPTIONS" ]
```

生效规则（自上而下）：

- 若匹配到 exclude 中任意一个条件，则不捕获、不执行规则。
  - 不做 HTTPS 解密（TLS 直通）仅对 exclude.hosts 生效对应域名的 HTTPS 不解密、直接透传。
  - exclude.paths / exclude.methods 仅影响捕获与规则。
- 若 include 全为空（未配置 hosts/paths/methods），默认捕获全部请求。
- 若 include 配置了任一类（hosts/paths/methods），只要命中任一类即捕获；三类都未命中则不捕获。

说明：

- hosts、paths 支持正则；**hosts 还支持通配符**：写 `*.apple.com`、`*cdn-apple*` 等（`*` 匹配任意、`?` 匹配单字符、`.` 为字面点），含 `\`、`^`、`$` 时按正则处理；hosts 大小写不敏感，paths 大小写敏感。
- methods 自动转为大写进行匹配。

**App Store / iTunes 打不开时**：1）启动必须用 `--config /path/to/你的配置.yaml`，否则会读默认路径（如 `~/.uproxier/config.yaml`），exclude 可能未生效；2）exclude.hosts 需覆盖 App Store 会用到的域名，建议至少包含：`.*\\.apple\\.com$`、`.*\\.cdn-apple\\.com$`（如 store.storeimages.cdn-apple.com）、`.*\\.itunes\\.apple\\.com$`、`.*\\.icloud\\.com$`、`.*\\.mzstatic\\.com$`、`.*\\.aaplimg\\.com$`；3）不加 `-s` 启动时，若 TLS 直通生效会在控制台看到 `TLS 直通（exclude.hosts）: xxx`，若无该日志说明配置未加载或域名未命中。

```
action: <行为名>
params: <参数，随行为不同而异>
```

### 规则配置

项目支持在 `config.yaml` 中定义规则，包含请求/响应修改、Mock、延迟等。当前版本使用"通用规则模型"并已弃用旧键（conditions/actions）。

#### 配置继承

支持使用 `extends` 字段实现配置继承，减少重复配置：

```yaml
# base_config.yaml
rules:
  - name: "基础规则"
    enabled: true
    priority: 100
    match:
      host: "^api\\.example\\.com$"
    response_pipeline:
      - action: set_header
        params:
          X-Custom-Header: "base-value"

# main_config.yaml
extends: "./base_config.yaml"  # 继承基础配置
rules:
  - name: "扩展规则"
    enabled: true
    priority: 200
    match:
      host: "^api\\.example\\.com$"
      path: "^/v1/"
    response_pipeline:
      - action: mock_response
        params:
          file: "../../MockData/response.json"  # 相对路径基于配置文件位置解析
```

**路径解析规则**：
- 配置文件中的相对路径（如 `file: "../../MockData/response.json"`）相对于配置文件本身解析
- 支持 `../` 等相对路径符号
- 继承配置的路径也会正确解析

#### 通用规则模型

每条规则由以下字段构成：

- name: 规则名称（字符串）
- enabled: 是否启用（布尔）
- priority: 优先级（数值，越大越先执行）
- stop_after_match: 命中后是否停止后续规则（布尔，默认 false）
- match: 命中条件（对象，字段按 AND 关系组合）
    - host: 主机匹配正则（字符串，推荐使用锚点 ^…$，大小写不敏感）
    - path: 路径匹配正则（字符串，推荐以 ^/ 开头）
    - method: HTTP 方法（字符串，如 GET/POST，大小写不敏感）
    - keywords: 请求参数关键字（通常用于 GET 请求匹配，多个关键字可以使用数组["a", "b", "c"] 请求参数中包含任意一个关键字即匹配成功）
- request_pipeline: 请求阶段流水线（数组，按顺序执行）
- response_pipeline: 响应阶段流水线（数组，按顺序执行）

#### 流水线步骤（Action）通用格式：

支持的行为（请求阶段 request_pipeline）：

- set_header
    - params: { <Header-Name>: <Value>, ... }
    - 作用：设置或覆盖请求头
- remove_header
    - params: [ "Header-Name", ... ]
    - 作用：删除请求头
- rewrite_url
    - params: { from: "字符串", to: "字符串" }
    - 作用：对当前 URL 做字符串替换
- redirect
    - params: "https://target.example.com/path" 或 { to: "…" }
    - 作用：重定向请求到指定 URL
- replace_body
    - params: { from: "字符串", to: "字符串" }
    - 作用：将请求体按字符串替换（仅对可解码文本生效）
- short_circuit
    - params: { status/status_code?, headers?, content?, file? }
    - 作用：请求阶段本地直返；`file` 与 `content` 同时存在时优先 `file`

支持的行为（响应阶段 response_pipeline）：

- set_status
    - params: 200（数值）
    - 作用：设置响应状态码
- set_header
    - params: { <Header-Name>: <Value>, ... }
    - 作用：设置或覆盖响应头
- remove_header
    - params: [ "Header-Name", ... ]
    - 作用：删除响应头
- replace_body
    - params: { from: "字符串", to: "字符串" }
    - 作用：将响应体按字符串替换（仅对可解码文本生效）
- mock_response
    - params:
        - status_code: 200（可选）
        - headers: { ... }（可选）
        - content: 对象或字符串（与 headers 一起返回）
        - file: 本地文件路径（优先于 content）
    - 作用：完全替换上游响应
- delay
    - params（任选，单位 ms）：
        - time: 基准延迟
        - jitter: 抖动范围（0~jitter）
        - distribution: uniform|normal|exponential（与 time/jitter 组合）
        - p50/p95/p99: 分位数近似延迟
    - 作用：按配置延迟发送响应（延迟仅影响当前请求，不阻塞其它连接）
- short_circuit
    - params: { status: 200, headers: {...}, content: {...或字符串}, file: 本地文件路径 }
    - 作用：本地直接返回，等价于 mock_response

匹配规则说明：

- 仅 host：只校验 host；仅 path：只校验 path
- 同时配置 host 与 path 与 method：三者 AND 关系，全部命中才执行
- host 为不区分大小写正则；path 为正则（建议 ^/ 起始）

规则之间的执行顺序：

- 先按 priority 从大到小排序，逐条尝试命中
- 命中后执行其 request_pipeline → 发起上游 → 执行其 response_pipeline
- 若 stop_after_match=true，则该规则执行后不再尝试后续规则

#### 示例

项目内置了部分规则示例，可以通过 CLI 命令查看和使用：

```bash
# 从 PyPI 安装后使用
# 查看所有可用示例
uproxier examples --list

# 查看示例说明文档
uproxier examples --readme

# 复制示例到当前目录进行修改
uproxier examples --copy 01_set_header.yaml

# 从源码运行
# 查看所有可用示例
python3 -m uproxier examples --list

# 查看示例说明文档
python3 -m uproxier examples --readme

# 复制示例到当前目录进行修改
python3 -m uproxier examples --copy 01_set_header.yaml
```

示例文件包括：

- **基础 Action 示例**：设置/移除请求头、URL 重写、参数修改等
- **响应处理示例**：Mock 响应、延迟、条件执行等
- **匹配条件示例**：各种 host、path、method 组合
- **复杂工作流示例**：多规则组合、优先级控制等

参照这些示例在项目的 `config.yaml` 中实现你的规则配置。

#### 规则引擎扩展与字段说明

- 顶层字段（每条规则）
    - `name`（字符串）：规则名
    - `enabled`（布尔）：是否启用
    - `priority`（数值）：优先级，越大越先执行
    - `stop_after_match`（布尔）：命中后是否短路后续规则
    - `match`（对象）：命中条件（AND 关系）
        - `host`：主机正则（不区分大小写，建议使用 ^...$）
        - `path`：路径正则（建议以 ^/ 开头）
        - `method`：HTTP 方法（GET/POST/...）
        - `keywords`: 请求参数关键字（单个关键字可使用字符串，多个关键字使用数组传递）
    - `request_pipeline` / `response_pipeline`（数组）：流水线动作，按顺序执行

- 请求阶段动作（request_pipeline）
    - `set_header`：设置/覆盖请求头（params: { Header: Value })
    - `remove_header`：删除请求头（params: [Header, ...]）
    - `rewrite_url`：替换 URL 片段（params: { from, to }）
    - `redirect`：重定向请求（params: "url" 或 { to: "url" }）
    - `replace_body`：请求体字符串替换（params: { from, to }）
    - `set_query_param`：设置/新增查询参数（params: { key: value, ... }）
    - `set_body_param`：设置/新增请求体参数
        - 表单：application/x-www-form-urlencoded → { k: v }
        - JSON 扁平：{ a.b: 1, items.0.name: "foo" }（点路径/数组索引）
        - JSON 单键：{ path: "a.b", value: 1 }（兼容 to）
        - 自动更新 Content-Length
    - `set_variable`：设置全局变量（支持跨请求数据共享）
        - 请求阶段：可设置基于请求的变量，支持内置变量（{{timestamp}}, {{datetime}}, {{random}}）
        - 使用示例：
          ```yaml
          # 设置请求相关的变量
          - action: set_variable
            params:
              request_id: "{{timestamp}}"
              request_time: "{{datetime}}"
          ```

- 响应阶段动作（response_pipeline）
    - `set_status`：设置状态码（params: 200）
    - `set_header` / `remove_header`：设置/删除响应头
    - `replace_body`：响应体字符串替换（params: { from, to }）
    - `replace_body_json`：精确修改 JSON 字段
        - 扁平直传（推荐）：params 下直接写路径键：{ status: 1, data.id: "abc" }
        - 批量对象：{ values: { status: 1, data.id: "abc" } }
        - 批量数组：{ values: [ { path: "status", value: 1 }, ... ] }
        - 单键糖：{ path: "status", value: 1 }
    - `set_variable`：设置全局变量（支持跨请求数据共享）
        - 响应阶段：可设置基于响应数据的变量，支持 {{data.field}} 格式提取响应字段
        - **重要**：`data` 是系统自动创建的上下文字段，包装整个响应 JSON 数据
        - 支持内置变量（{{timestamp}}, {{datetime}}, {{random}}）和全局变量
        - 使用示例：
          ```yaml
          # 从响应中提取数据
          - action: set_variable
            params:
              user_id: "{{data.user_id}}"
              username: "{{data.username}}"
              auth_token: "{{data.token}}"
              # 如果响应是 {"appVersion": "1.2.1"}，则使用：
              app_version: "{{data.appVersion}}"
          
          # 在其他请求中使用
          - action: replace_body_json
            params:
              values:
                "user_id": "{{user_id}}"
                "username": "{{username}}"
                "timestamp": "{{timestamp}}"
          ```
    - `mock_response`：完全替换响应
        - params: { status_code?, headers?, content? | file?, redirect_to?/location? }
        - headers 采用“覆盖/新增”，不会清空其它上游头
        - file：从磁盘读取文件内容（bytes）作为响应体；相对路径基于当前工作目录，支持 ~；当未显式设置 Content-Type 时会按扩展名尝试推断（如 .json →
          application/json）；响应头会附加 `X-Mocked-From-File: <绝对路径>` 便于排查
            - 示例：
          ```yaml
          response_pipeline:
            - action: mock_response
              params:
                status_code: 200
                headers: { Cache-Control: no-cache }
                file: mocks/demo.json
          ```
        - redirect_to/location：若未指定 status_code，默认 302，并设置 Location
    - `delay`：真实延迟发送
        - params: { time?, jitter?, distribution?, p50?, p95?, p99? }（单位 ms）
        - 实现方式：抓取 flow.reply 并延后下发；响应头回写 X-Delay-Applied / X-Delay-Effective
    - `remove_json_field`：移除 JSON 响应中的字段
        - params: { fields: string | array }（要删除的字段名，支持字符串或数组）
        - 支持嵌套字段删除（如 "user.metadata"）
        - 示例：
          ```yaml
          response_pipeline:
            - action: remove_json_field
              params:
                fields: ["password", "token", "debug_info"]
          ```
    - `short_circuit`：本地直返（等价于 mock_response）

- 模板变量支持
    - 内置变量：
        - `{{timestamp}}`：当前时间戳（秒）
        - `{{datetime}}`：当前日期时间（ISO 格式）
        - `{{random}}`：随机数（1000-9999）
    - 全局变量：
        - `{{变量名}}`：通过 `set_variable` 设置的全局变量
        - 支持跨请求数据共享，变量在代理运行期间持续有效
    - 响应数据变量：
        - `{{data.field}}`：从响应 JSON 中提取字段值
        - **重要**：`data` 是系统自动创建的上下文字段，包装整个响应数据
        - 支持嵌套字段：`{{data.user.profile.name}}`
        - 支持数组索引：`{{data.items.0.title}}`
        - **示例**：如果响应是 `{"appVersion": "1.2.1"}`，则使用 `{{data.appVersion}}` 获取 "1.2.1"
    - 使用场景：
        - 在 `set_variable` 中提取响应数据：`user_id: "{{data.user_id}}"`
        - 在 `replace_body_json` 中使用全局变量：`"user_id": "{{user_id}}"`
        - 在 `set_header` 中使用时间戳：`X-Request-Time: "{{timestamp}}"`

- 执行与可观测性
    - 按 priority 从大到小遍历；命中后执行 request_pipeline → 上游 → response_pipeline
    - `stop_after_match=true`：该规则执行后不再尝试后续规则
    - 响应阶段仅遍历 enabled 规则；命中规则名写入响应头 `X-Rule-Name`

#### 更多示例

替换响应 JSON 指定字段（单键 + 扁平直传）：

```
- name: Replace response JSON
  enabled: true
  priority: 90
  match:
    host: "^api\.example\.com$"
    path: "^/v1/data$"
  response_pipeline:
    - action: replace_body_json
      params:
        status: 1
        data.request_id: "mock-xyz"
```

多次字符串替换：

```
- name: Replace body strings
  enabled: true
  priority: 60
  match:
    host: "^www\.baidu\.com$"
    method: GET
  response_pipeline:
    - action: replace_body
      params: { from: "百度", to: "Google" }
    - action: replace_body
      params: { from: "你就知道", to: "啥都不知道" }
```

302 重定向：

```
- name: Redirect to landing
  enabled: true
  priority: 60
  match:
    host: "^api\.example\.com$"
    path: "^/old$"
  response_pipeline:
    - action: mock_response
      params:
        redirect_to: "https://example.com/new"
```

请求参数修改：

```
- name: Request param edits
  enabled: true
  priority: 70
  match:
    host: "^api\.example\.com$"
    path: "^/old$"
    method: POST
  request_pipeline:
    - action: set_query_param
      params: { A: 0, b: "xyz" }
    - action: set_body_param
      params:
        properties.duration: 1000
```

#### 注意事项

- Content-Type：
    - replace_body_json 仅在原头非 JSON 时才补齐 application/json; charset=utf-8
    - set_body_param 会更新 Content-Length
- `values` 冲突优先级：
    - replace_body_json 优先按扁平直传应用（允许把 `values` 当业务字段名），若无修改才解析 `values` 批量语法，最后兜底单键 `{ path, value }`
- 禁用规则：
    - enabled=false 的规则在请求与响应阶段都会跳过；控制台加载日志会输出“加载了 N 条规则（启用 M 条）”
- 可观测头：
    - 命中规则：X-Rule-Name
    - 延迟：X-Delay-Applied / X-Delay-Effective

## Web 界面

访问 `http://<本机IP>:8002` 查看 Web 界面，功能包括：

- 📊 实时流量统计
- 📋 请求/响应详情
- 🔍 流量搜索
- 📈 性能分析
- 💾 数据导出（/api/export?format=json|jsonl|csv&limit=1000）

## 证书管理

### 自动安装

```bash
# 从 PyPI 安装后使用
uproxier cert
# 选择 "安装证书到系统"

# 从源码运行
python3 -m uproxier cert
# 选择 "安装证书到系统"
```

### 手动安装

⚠️ **重要提醒**：只安装证书文件，不要安装包含私钥的文件（`mitmproxy-ca-key.pem` 和 `mitmproxy-ca.pem`）！

```
# 证书文件存储在用户目录
~/.uproxier/                    # 用户配置目录
├── config.yaml                 # 默认配置文件
└── certificates/               # 证书目录
    ├── mitmproxy-ca-cert.pem   # PEM 格式证书（mitmproxy 使用 + 用户安装）
    ├── mitmproxy-ca-key.pem    # 私钥文件（mitmproxy 使用，⚠️ 不要安装）
    ├── mitmproxy-ca.pem        # 合并证书+私钥（mitmproxy 使用，⚠️ 不要安装）
    └── mitmproxy-ca-cert.der   # DER 格式证书（用户安装）
```

#### macOS

```bash
# 推荐使用 PEM 格式（双击证书文件或使用命令行）
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.uproxier/certificates/mitmproxy-ca-cert.pem

# 或者使用 DER 格式
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.uproxier/certificates/mitmproxy-ca-cert.der
```

#### Windows

```bash
# 推荐使用 DER 格式
certutil -addstore -f ROOT ~/.uproxier/certificates/mitmproxy-ca-cert.der

# 或者使用 PEM 格式
certutil -addstore -f ROOT ~/.uproxier/certificates/mitmproxy-ca-cert.pem
```

#### Linux

```bash
# 推荐使用 PEM 格式
sudo cp ~/.uproxier/certificates/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates

# 或者使用 DER 格式
sudo cp ~/.uproxier/certificates/mitmproxy-ca-cert.der /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

## 项目结构

```
UProxier/
├── requirements.txt    # 依赖列表
├── README.md           # GitHub 文档
├── README_PYPI.md      # PyPI 文档
├── API_USAGE.md        # API 使用文档
└── uproxier/           # 主包目录
    ├── __init__.py     # 包初始化
    ├── __main__.py     # 模块入口
    ├── cli.py          # 命令行工具
    ├── proxy_server.py # 主代理服务器
    ├── rules_engine.py # 规则引擎
    ├── certificate_manager.py # 证书管理
    ├── web_interface.py # Web 界面
    ├── action_processors.py # 动作处理器
    ├── config_validator.py # 配置验证器
    ├── exceptions.py   # 异常定义
    ├── utils/           # 通用工具
    ├── version.py      # 版本信息
    ├── templates/      # Web 模板
    └── examples/       # 内置示例（14个规则示例 + 配置示例）
```

## 故障排除

### 常见问题

1. **安装后 uproxier 命令不可用**
   ```bash
   # 如果使用 pyenv，检查版本设置
   pyenv versions  # 查看可用版本
   pyenv global    # 查看当前全局版本
   
   # 如果全局版本不是安装 uproxier 的版本，设置为正确的版本
   pyenv global 3.10.6  # 替换为你的 Python 版本
   
   # 如果使用 pyenv，确保 pyenv 已正确初始化
   # 在 ~/.zshrc 或 ~/.bashrc 中添加：
   echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
   echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
   echo 'eval "$(pyenv init --path)"' >> ~/.zshrc
   echo 'eval "$(pyenv init -)"' >> ~/.zshrc
   source ~/.zshrc
   
   # 检查安装位置
   python3 -c "import sys; print(sys.executable.replace('python3', 'uproxier'))"
   
   # 如果仍不可用，确保 Python bin 目录在 PATH 中
   export PATH="$(python3 -c "import sys; print(sys.executable.replace('python3', ''))"):$PATH"
   ```

2. **证书错误**
    - 确保证书已正确安装到系统
    - 重新生成证书：`uproxier cert`（PyPI 安装）或 `python3 -m uproxier cert`（源码安装）

3. **端口被占用**
    - 使用不同的端口：`uproxier start --port 8003`（PyPI 安装）或 `python3 -m uproxier start --port 8003`（源码安装）

4. **规则不生效**
    - 检查规则配置是否正确
    - 确认规则已启用
    - 查看日志输出

5. **HTTPS 连接失败**
    - 确保证书已安装
    - 检查浏览器代理设置
    - 尝试访问 HTTP 网站测试

### 日志

启用详细日志：

```bash
# 从 PyPI 安装后使用
uproxier --verbose start

# 从源码运行
python3 -m uproxier --verbose start
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 参考

- [mitmproxy](https://mitmproxy.org/)

