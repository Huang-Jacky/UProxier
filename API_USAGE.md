# UProxier API 使用指南

## 概述

UProxier 提供了两种启动方式：
- **阻塞启动** (`start`): 同步方法，会阻塞当前线程
- **异步启动** (`start_async`): 异步方法，不会阻塞当前线程

## 基本用法

### 1. 阻塞启动

```python
from uproxier.proxy_server import ProxyServer

# 创建代理服务器实例（配置文件路径可选，默认使用 ~/.uproxier/config.yaml）
proxy = ProxyServer("config.yaml")

# 阻塞启动
proxy.start(8001, 8002)
# 这里不会执行，直到服务器停止
```

### 2. 异步启动

**简单使用（推荐）**：
```python
from uproxier.proxy_server import ProxyServer
import time

# 创建代理服务器实例（配置文件路径可选，默认使用 ~/.uproxier/config.yaml）
proxy = ProxyServer("config.yaml", silent=True)

# 异步启动
proxy.start_async(8001, 8002)

# 继续执行其他代码
print("服务器已在后台启动")
time.sleep(1)

# 执行测试或其他逻辑
print("执行测试...")

# 停止服务器
proxy.stop()
```

**需要进程管理时**：
```python
from uproxier.proxy_server import ProxyServer

# 创建代理服务器实例（配置文件路径可选，默认使用 ~/.uproxier/config.yaml）
proxy = ProxyServer("config.yaml", silent=True)

# 异步启动（保存进程对象）
process = proxy.start_async(8001, 8002)
print(f"服务器已启动 (PID: {process.pid})")

# 检查进程状态
if process.poll() is None:
    print("服务器正在运行")
else:
    print("服务器已停止")

# 停止服务器
proxy.stop()
```

## 完整示例

```python
#!/usr/bin/env python3
from uproxier.proxy_server import ProxyServer
import time
import requests

def test_proxy():
    # 创建代理服务器实例（配置文件路径可选，默认使用 ~/.uproxier/config.yaml）
    proxy = ProxyServer("config.yaml", silent=True)
    
    try:
        # 启动服务器
        process = proxy.start_async(8001, 8002)
        print(f"代理服务器已启动 (PID: {process.pid})")
        
        # 等待服务器完全启动
        time.sleep(2)
        
        # 测试 Web 界面
        response = requests.get("http://localhost:8002")
        print(f"Web界面状态: {response.status_code}")
        
        # 执行其他测试...
        print("执行测试中...")
        time.sleep(1)
        
    except Exception as e:
        print(f"测试失败: {e}")
    finally:
        # 确保停止服务器
        proxy.stop()
        print("服务器已停止")

if __name__ == "__main__":
    test_proxy()
```

## 参数说明

### ProxyServer 构造函数

```python
ProxyServer(
    config_path="config.yaml",    # 配置文件路径（可选，默认使用 ~/.uproxier/config.yaml）
    save_path=None,               # 流量保存路径（JSONL格式）
    silent=False,                 # 是否静默模式
    enable_https=None             # 是否启用HTTPS拦截
)
```

### start_async 方法

```python
process = proxy.start_async(
    host="0.0.0.0",    # 代理服务器地址
    port=8001,           # 代理服务器端口
    web_port=8002        # Web界面端口
)
```

**注意**：`start_async` 方法的参数与 `start` 方法完全相同，区别仅在于启动方式：
- `start`: 同步启动，会阻塞当前线程
- `start_async`: 异步启动，非阻塞，立即返回

返回 `subprocess.Popen` 对象，可以用于：
- `process.pid`: 获取进程ID
- `process.poll()`: 检查进程是否还在运行（返回 None 表示运行中）
- `process.terminate()`: 发送 SIGTERM 信号
- `process.kill()`: 发送 SIGKILL 信号

## 注意事项

1. **异步启动**：`start_async` 方法使用 `subprocess.Popen` 启动后台进程，适合在代码中使用
2. **进程管理**：异步启动的进程可以通过 `proxy.stop()` 方法停止
3. **错误处理**：建议使用 try-except 块包装启动和停止逻辑
4. **资源清理**：确保在 finally 块中调用 `proxy.stop()` 清理资源
5. **端口冲突**：确保使用的端口没有被其他进程占用
6. **配置文件**：如果不指定 `config_path`，将使用默认配置文件 `~/.uproxier/config.yaml`
7. **证书管理**：首次启动会自动生成证书到 `~/.uproxier/certificates/` 目录
8. **抓包文件**：如果指定 `save_path`，每次启动都会覆盖该文件（不是追加）


## 配置继承示例

UProxier 支持配置继承，可以在 API 中使用：

```python
from uproxier.proxy_server import ProxyServer

# 使用继承配置的配置文件
proxy = ProxyServer("main_config.yaml", silent=True)

# main_config.yaml 可以继承 base_config.yaml
# extends: "./base_config.yaml"
# rules:
#   - name: "扩展规则"
#     # ... 其他配置
```

**配置继承特点**：
- 支持 `extends` 字段实现配置继承
- 相对路径基于配置文件位置解析
- 支持多重继承和路径合并

## 故障排除

1. **端口被占用**：检查端口是否被其他进程使用
2. **权限问题**：确保有权限绑定指定端口
3. **配置文件错误**：检查 `config.yaml` 文件格式
4. **进程启动失败**：检查错误日志，通常是配置或权限问题
5. **证书问题**：确保证书已正确安装到系统
6. **路径解析错误**：检查配置文件中的相对路径是否正确
