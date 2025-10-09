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

### 高级功能示例

- **12_match_conditions.yaml** - 各种匹配条件组合
- **13_priority_stop_after_match.yaml** - 优先级和停止匹配
- **14_complex_workflows.yaml** - 复杂工作流组合
- **15_global_variables.yaml** - 全局变量基础用法
- **16_global_variables_complete.yaml** - 全局变量完整示例
- **17_remove_json_field.yaml** - 移除 JSON 字段示例

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
- `set_variable` - 设置全局变量
- `short_circuit` - 请求阶段短路

### 响应阶段动作 (response_pipeline)

- `set_status` - 设置状态码
- `set_header` - 设置响应头
- `remove_header` - 移除响应头
- `replace_body` - 替换响应体
- `replace_body_json` - 精确修改 JSON 字段
- `remove_json_field` - 移除 JSON 字段
- `mock_response` - Mock 响应
- `delay` - 延迟响应
- `set_variable` - 设置全局变量
- `conditional` - 条件执行
- `short_circuit` - 响应阶段短路

## 注意事项

1. **优先级**：数字越大优先级越高，先执行
2. **停止匹配**：`stop_after_match: true` 时，该规则执行后不再执行后续规则
3. **正则表达式**：host 和 path 支持正则表达式，注意转义特殊字符
4. **JSON 修改**：`replace_body_json` 支持点路径语法（如 `user.profile.name`）
5. **JSON 字段删除**：`remove_json_field` 支持删除顶级字段、嵌套字段、数组元素和数组中对象的字段
6. **全局变量**：`set_variable` 支持跨请求的数据传递，支持模板变量（`{{timestamp}}`、`{{data.field}}`）
7. **文件路径**：`mock_response` 的 `file` 参数支持相对路径和绝对路径
8. **延迟分布**：支持 uniform、normal、exponential 三种分布模式

## 新功能详解

### 全局变量 (set_variable)

支持跨请求的数据传递，在请求或响应阶段设置变量：

```yaml
- action: set_variable
  params:
    user_id: "{{data.user_id}}"      # 从响应数据中提取
    timestamp: "{{timestamp}}"      # 使用内置变量
    custom_value: "fixed_value"      # 设置固定值
```

### JSON 字段删除 (remove_json_field)

支持多种删除模式：

```yaml
- action: remove_json_field
  params:
    fields: [
      "sensitive_field",             # 删除顶级字段
      "data.nested_field",           # 删除嵌套字段
      "users.1",                     # 删除数组元素
      "users.0.secret",              # 删除数组中对象的字段
      "matrix.0.1"                   # 删除多层嵌套数组元素
    ]
```

## 调试技巧

1. **查看规则命中**：响应头中的 `X-Rule-Name` 显示命中的规则
2. **查看延迟信息**：响应头中的 `X-Delay-Applied` 和 `X-Delay-Effective` 显示延迟信息
3. **动作调试信息**：当动作执行出错时，响应头会包含 `X-ActionName-Error` 调试信息：
   - `X-SetHeader-Error: Error: 具体错误`
   - `X-MockResponse-Error: Error: 具体错误`
   - `X-ReplaceBodyJson-Error: Error: 具体错误`
   - `X-Delay-Error: Error: 具体错误`
4. **Web 界面**：访问 `http://localhost:8002` 查看实时流量和规则效果
5. **日志输出**：启动时设置 `--verbose` 查看详细日志
