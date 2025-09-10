# UProxier 规则示例

UProxier 规则引擎的各种使用示例。

## 示例文件说明

### 基础 Action 示例

- **01_set_header.yaml** - 设置请求/响应头
- **02_remove_header.yaml** - 移除请求/响应头
- **03_rewrite_url.yaml** - URL 重写和重定向
- **04_set_query_param.yaml** - 设置查询参数
- **05_set_body_param.yaml** - 设置请求体参数
- **06_replace_body.yaml** - 替换请求/响应体内容
- **07_replace_body_json.yaml** - 精确修改 JSON 响应字段
- **08_mock_response.yaml** - Mock 响应（内联内容和文件）
- **09_delay.yaml** - 响应延迟（多种分布模式）
- **10_conditional.yaml** - 条件执行
- **11_short_circuit.yaml** - 短路响应

### 匹配和流程控制

- **12_match_conditions.yaml** - 各种匹配条件组合
- **13_priority_stop_after_match.yaml** - 优先级和停止匹配
- **14_complex_workflows.yaml** - 复杂工作流组合

## 使用方法

1. **复制示例到主配置**：
   ```bash
   # 复制单个示例到主配置文件
   cp examples/01_set_header.yaml config.yaml
   ```

2. **合并多个示例**：
   ```bash
   # 手动编辑 config.yaml，将多个示例的 rules 部分合并
   ```

3. **测试规则**：
   ```bash
   # 启动代理服务器
   python3 cli.py start
   
   # 在浏览器中访问匹配的 URL 进行测试
   ```

## 规则结构说明

每个规则包含以下字段：

```yaml
rules:
  - name: "规则名称"           # 必填：规则描述
    enabled: true             # 可选：是否启用（默认 true）
    priority: 10              # 可选：优先级，数字越大越先执行（默认 0）
    stop_after_match: false   # 可选：命中后是否停止后续规则（默认 false）
    match:                    # 必填：匹配条件
      host: "^api\\.example\\.com$"  # 主机匹配（正则）
      path: "^/v1/"                  # 路径匹配（正则）
      method: "GET"                  # HTTP 方法匹配
    request_pipeline: []      # 可选：请求阶段动作列表
    response_pipeline: []     # 可选：响应阶段动作列表
```

## 匹配条件

- **host**: 主机名正则匹配（不区分大小写）
- **path**: 路径正则匹配（区分大小写）
- **method**: HTTP 方法匹配（GET, POST, PUT, DELETE 等）

## 动作类型

### 请求阶段动作 (request_pipeline)

- `set_header` - 设置请求头
- `remove_header` - 移除请求头
- `rewrite_url` - 重写 URL
- `redirect` - 重定向请求
- `replace_body` - 替换请求体
- `set_query_param` - 设置查询参数
- `set_body_param` - 设置请求体参数
- `short_circuit` - 请求阶段短路

### 响应阶段动作 (response_pipeline)

- `set_status` - 设置状态码
- `set_header` - 设置响应头
- `remove_header` - 移除响应头
- `replace_body` - 替换响应体
- `replace_body_json` - 精确修改 JSON 字段
- `mock_response` - Mock 响应
- `delay` - 延迟响应
- `conditional` - 条件执行
- `short_circuit` - 响应阶段短路

## 注意事项

1. **优先级**：数字越大优先级越高，先执行
2. **停止匹配**：`stop_after_match: true` 时，该规则执行后不再执行后续规则
3. **正则表达式**：host 和 path 支持正则表达式，注意转义特殊字符
4. **JSON 修改**：`replace_body_json` 支持点路径语法（如 `user.profile.name`）
5. **文件路径**：`mock_response` 的 `file` 参数支持相对路径和绝对路径
6. **延迟分布**：支持 uniform、normal、exponential 三种分布模式

## 调试技巧

1. **查看规则命中**：响应头中的 `X-Rule-Name` 显示命中的规则
2. **查看延迟信息**：响应头中的 `X-Delay-Applied` 和 `X-Delay-Effective` 显示延迟信息
3. **Web 界面**：访问 `http://localhost:8002` 查看实时流量和规则效果
4. **日志输出**：启动时设置 `--verbose` 查看详细日志
