# UProxier · Proxy Server

🌐 Language: 🇺🇸 English | [🇨🇳 中文](README.md)


A complete proxy software solution based on mitmproxy, supporting HTTP/HTTPS proxy, request interception, rule configuration, and Web UI.

## Features

- 🔄 **HTTP/HTTPS Proxy**: Full proxy with HTTPS decryption toggle (config or CLI override)
- 🛡️ **Certificate Management**: Automatic generation/validation/installation of mitmproxy CA certificates
- 📋 **Rule Engine**: Multi-action stacking, priority, short-circuit on match (stop_after_match)
    - mock_response (supports local file), modify_headers, modify_content, redirect
    - modify_response_headers, modify_response_content, modify_status
    - delay_response (real-time delayed sending), conditional_response (conditional branching)
    - Config inheritance (extends) support with automatic relative path resolution
- 💾 **Persistence**: Save captured requests as JSONL (--save, overwrite mode)
- 🌐 **Web UI**: Real-time traffic, detailed view by clicking, search, clear, fully offline
- 🎯 **CLI Tool**: start/init/cert/version/examples/validate & silent mode (--silent)
- 📊 **Capture Control**: Streaming/large file toggle, threshold and binary save control (via config.yaml)
- 🔧 **Configuration Management**: Unified config directory (~/.uproxier/), YAML config + CLI override
- ✅ **Config Validation**: Complete validation system checking syntax, types, file existence, etc.

## Installation

### From PyPI (Recommended)

```bash
pip install uproxier
```

### From Source

```bash
git clone https://github.com/Huang-Jacky/UProxier.git
cd UProxier
pip install -r requirements.txt
```

### Requirements

- Python 3.12+
- OpenSSL (for certificate generation)

## Quick Start

### From PyPI (Recommended)

1. Install UProxier

```bash
pip install uproxier
```

2. Start the proxy (first start will auto-generate CA certificates in `~/.uproxier/certificates/`; the startup panel will display certificate path and validity period)

```bash
uproxier start
```

3. Install certificate

```bash
uproxier cert
# Choose to install to system or follow the prompts for manual installation
```

### From Source

1. Install UProxier

```bash
git clone https://github.com/Huang-Jacky/UProxier.git
cd UProxier
pip install -r requirements.txt
```

2. Start the proxy (first start will auto-generate CA certificates in `~/.uproxier/certificates/`; the startup panel will display certificate path and validity period)

```bash
python3 -m uproxier start
```

3. Install certificate

```bash
python3 -m uproxier cert
# Choose to install to system or follow the prompts for manual installation
```

### First Time Usage (Auto-generate Certificate)

3. Install certificate

- **Web UI Download**: Open "Scan to Download Certificate" in the top-right corner of Web UI, access the download link in a mobile browser to install (downloaded as DER format, filename `uproxier-ca.cer`)
- **Command Line Installation**:

```bash
# After PyPI installation
uproxier cert

# From source
python3 -m uproxier cert
# Choose to install to system or follow the prompts for manual installation
```

4. Configure HTTP(S) proxy on the device/browser to this machine's IP and startup port

### 1. Initialize Configuration (Optional)

Certificates are auto-generated on first start. For manual certificate generation or installation:

```bash
python3 -m uproxier cert
```

### 2. Configure Browser Proxy

Configure proxy settings in browser/device:

- Proxy Address: `<Your Machine IP>`
- Port: `8001`

## Usage Guide

### Command Line Tool

#### Help Information

```
# After PyPI installation
uproxier --help
uproxier start --help      # View all parameters for start command
uproxier examples --help   # View all parameters for examples command
uproxier cert --help       # View all parameters for cert command
uproxier init --help       # View all parameters for init command
uproxier info --help       # View all parameters for info command
uproxier validate --help   # View all parameters for validate command

# From source
python3 -m uproxier --help
python3 -m uproxier start --help      # View all parameters for start command
python3 -m uproxier examples --help   # View all parameters for examples command
python3 -m uproxier cert --help       # View all parameters for cert command
python3 -m uproxier init --help       # View all parameters for init command
python3 -m uproxier info --help       # View all parameters for info command
python3 -m uproxier validate --help   # View all parameters for validate command
```

#### Global Options

```bash
# After PyPI installation
uproxier --verbose          # Verbose output
uproxier --config <path>    # Specify config file path
uproxier --version          # Show version info

# From source
python3 -m uproxier --verbose          # Verbose output
python3 -m uproxier --config <path>    # Specify config file path
python3 -m uproxier --version          # Show version info
```

#### Main Commands

**Start Proxy Server**

```bash
# After PyPI installation
uproxier start \
  --port 8001 \                   # Proxy server port
  --web-port 8002 \               # Web UI port
  --config <path> \               # Config file path (optional, defaults to ~/.uproxier/config.yaml)
  --save ./logs/traffic.jsonl \   # Save request data to file (JSONL format)
  --enable-https \                # Enable HTTPS decryption (override config)
  --disable-https \               # Disable HTTPS decryption (override config)
  --silent                        # Silent mode, no output
  --daemon                        # Start in daemon mode

# From source
python3 -m uproxier start \
  --port 8001 \                   # Proxy server port
  --web-port 8002 \               # Web UI port
  --config <path> \               # Config file path (optional, defaults to ~/.uproxier/config.yaml)
  --save ./logs/traffic.jsonl \   # Save request data to file (JSONL format)
  --enable-https \                # Enable HTTPS decryption (override config)
  --disable-https \               # Disable HTTPS decryption (override config)
  --silent                        # Silent mode, no output
  --daemon                        # Start in daemon mode
```

**Certificate Management**

```bash
# After PyPI installation
uproxier cert               # Manage certificates (generate, install, clean)

# From source
python3 -m uproxier cert               # Manage certificates (generate, install, clean)
```

**Server Control**

```bash
# After PyPI installation
uproxier status             # Check server status
uproxier stop               # Stop background running server

# From source
python3 -m uproxier status             # Check server status
python3 -m uproxier stop               # Stop background running server
```

**Initialize Configuration**

```bash
# After PyPI installation
uproxier init --config <path>                 # Specify config file path

# From source
python3 -m uproxier init --config <path>                 # Specify config file path
```

**Version Information**

```bash
# After PyPI installation
uproxier info               # Show version info

# From source
python3 -m uproxier info               # Show version info
```

**Configuration Validation**

```bash
# After PyPI installation
uproxier validate <config_file>                    # Validate config file
uproxier validate <config_file> --validate-only    # Validation only, no full report
uproxier validate <config_file> --format json      # Output JSON format report
uproxier validate <config_file> --output report.txt # Save report to file

# From source
python3 -m uproxier validate <config_file>                    # Validate config file
python3 -m uproxier validate <config_file> --validate-only    # Validation only, no full report
python3 -m uproxier validate <config_file> --format json      # Output JSON format report
python3 -m uproxier validate <config_file> --output report.txt # Save report to file
```

**Rule Examples Management**

```bash
# After PyPI installation
uproxier examples --list                    # List all available examples
uproxier examples --readme                  # Show examples documentation
uproxier examples --show <filename>         # Show specific example content
uproxier examples --copy <filename>         # Copy example to current directory

# From source
python3 -m uproxier examples --list                    # List all available examples
python3 -m uproxier examples --readme                  # Show examples documentation
python3 -m uproxier examples --show <filename>         # Show specific example content
python3 -m uproxier examples --copy <filename>         # Copy example to current directory
```

## API Usage

UProxier provides a complete Python API supporting both blocking and non-blocking startup.

### Quick Examples

**Blocking Startup**:
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml")
proxy.start(8001, 8002)  # Blocking startup, listen on 0.0.0.0:8001
```

**Async Startup**:
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml", silent=True)
proxy.start_async(8001, 8002)  # Non-blocking startup, listen on 0.0.0.0:8001
# Continue executing other code...
proxy.stop()
```

**Save Request Data**:
```python
from uproxier.proxy_server import ProxyServer

proxy = ProxyServer("config.yaml", save_path="requests.jsonl")
proxy.start(8001, 8002)  # Also save request data to file
```

### Detailed Documentation

Complete API usage guide: [API_USAGE.md](API_USAGE.md)

Includes:
- Blocking vs async startup use cases
- Complete parameter documentation and examples
- Process management and status checking
- Error handling and best practices
- Testing and automation scenario examples

### Capture Configuration

Basic capture is enabled by default; streaming/large file/binary content saving is disabled by default. You can directly edit the `capture` section in `config.yaml` to control:

```yaml
# Capture configuration
capture:
  # Enable streaming capture (default off to avoid performance overhead)
  enable_streaming: false
  # Enable large file capture (default off)
  enable_large_files: false
  # Large file threshold (bytes)
  large_file_threshold: 1048576  # 1MB
  # Save binary content (default off)
  save_binary_content: false
  # Enable HTTPS decryption (default on, can be overridden by CLI)
  enable_https: true

```

#### Capture Filtering (include / exclude)

Support whitelist/blacklist filtering under `capture` to control whether requests are written to UI and persistence:

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

Effective rules (top to bottom):

- If any condition in exclude matches, the request is not captured and rules are not executed.
  - HTTPS decryption (TLS passthrough) only applies to domains in exclude.hosts to skip HTTPS decryption.
  - exclude.paths / exclude.methods only affect capture and rules.
- If include is empty (hosts/paths/methods not configured), all requests are captured by default.
- If include has any configured type, capturing occurs if any type matches; no capture if none match.

Notes:

- hosts and paths support regex; **hosts also support wildcards**: write `*.apple.com`, `*cdn-apple*` etc. (`*` matches any, `?` matches single char, `.` is literal dot). Contains `\`, `^`, `$` are treated as regex.
- methods are auto-converted to uppercase for matching.

**When App Store / iTunes won't open**: 1) Startup must use `--config /path/to/your/config.yaml`, otherwise it reads default path (like `~/.uproxier/config.yaml`), exclude may not take effect; 2) Check exclude configuration.

```
action: <action name>
params: <parameters, varies by action>
```

### Rule Configuration

The project supports defining rules in `config.yaml`, including request/response modification, Mock, delay, etc. Current version uses "universal rule model" and has deprecated old keys (conditions/actions).

#### Configuration Inheritance

Support config inheritance using `extends` field to reduce repetition:

```yaml
# base_config.yaml
rules:
  - name: "Base Rule"
    enabled: true
    priority: 100
    match:
      host: "^api\\.example\\.com$"
    response_pipeline:
      - action: set_header
        params:
          X-Custom-Header: "base-value"

# main_config.yaml
extends: "./base_config.yaml"  # Inherit base config
rules:
  - name: "Extended Rule"
    enabled: true
    priority: 200
    match:
      host: "^api\\.example\\.com$"
      path: "^/v1/"
    response_pipeline:
      - action: mock_response
        params:
          file: "../../MockData/response.json"  # Relative path resolved based on config file location
```

**Path Resolution Rules**:
- Relative paths in config files (like `file: "../../MockData/response.json"`) are resolved relative to the config file itself
- Support `../` and other relative path symbols
- Inherited config paths are also resolved correctly

#### Universal Rule Model

Each rule consists of the following fields:

- name: Rule name (string)
- enabled: Whether enabled (boolean)
- priority: Priority (number, higher executes first)
- stop_after_match: Whether to stop subsequent rules after match (boolean, default false)
- match: Match conditions (object, fields combined with AND)
    - host: Host match regex (string, recommended to use anchors ^…$, case-insensitive)
    - path: Path match regex (string, recommended to start with ^/)
    - method: HTTP method (string, like GET/POST, case-insensitive)
    - keywords: Request parameter keywords (usually for GET request matching, multiple keywords use array["a", "b", "c"], matches if any keyword found)
- request_pipeline: Request stage pipeline (array, execute in order)
- response_pipeline: Response stage pipeline (array, execute in order)

#### Pipeline Step (Action) Common Format:

Supported actions (request_pipeline):

- set_header
    - params: { <Header-Name>: <Value>, ... }
    - Effect: Set or override request headers
- remove_header
    - params: [ "Header-Name", ... ]
    - Effect: Remove request headers
- rewrite_url
    - params: { from: "string", to: "string" }
    - Effect: String replace on current URL
- redirect
    - params: "https://target.example.com/path" or { to: "…" }
    - Effect: Redirect request to specified URL
- replace_body
    - params: { from: "string", to: "string" }
    - Effect: String replace on request body (text only)
- short_circuit
    - params: { status/status_code?, headers?, content?, file? }
    - Effect: Local direct return in request stage; `file` takes priority over `content`

Supported actions (response_pipeline):

- set_status
    - params: 200 (number)
    - Effect: Set response status code
- set_header
    - params: { <Header-Name>: <Value>, ... }
    - Effect: Set or override response headers
- remove_header
    - params: [ "Header-Name", ... ]
    - Effect: Remove response headers
- replace_body
    - params: { from: "string", to: "string" }
    - Effect: String replace on response body (text only)
- mock_response
    - params:
        - status_code: 200 (optional)
        - headers: { ... } (optional)
        - content: object or string (returned with headers)
        - file: local file path (priority over content)
    - Effect: Completely replace upstream response
- delay
    - params (optional, unit ms):
        - time: base delay
        - jitter: jitter range (0~jitter)
        - distribution: uniform|normal|exponential (combined with time/jitter)
        - p50/p95/p99: percentile approximate delay
    - Effect: Delay sending response by config (delay only affects current request, doesn't block others)
- short_circuit
    - params: { status: 200, headers: {...}, content: {...or string}, file: local file path }
    - Effect: Local direct return, equivalent to mock_response

Match rules explanation:

- Only host: validate only host; only path: validate only path
- Both host and path and method configured: AND relationship, execute if all match
- host is case-insensitive regex; path is regex (recommended to start with ^/)

Rule execution order:

- Sort by priority from high to low, try to match each rule
- After match, execute request_pipeline → upstream → response_pipeline
- If stop_after_match=true, don't try subsequent rules after this rule executes

#### Examples

Built-in rule examples are available, view and use via CLI commands:

```bash
# After PyPI installation
# View all available examples
uproxier examples --list

# View examples documentation
uproxier examples --readme

# Copy example to current directory for modification
uproxier examples --copy 01_set_header.yaml

# From source
# View all available examples
python3 -m uproxier examples --list

# View examples documentation
python3 -m uproxier examples --readme

# Copy example to current directory for modification
python3 -m uproxier examples --copy 01_set_header.yaml
```

Example files include:

- **Basic Action examples**: Set/remove request headers, URL rewrite, parameter modification, etc.
- **Response handling examples**: Mock responses, delay, conditional execution, etc.
- **Match condition examples**: Various host, path, method combinations
- **Complex workflow examples**: Multi-rule combinations, priority control, etc.

Refer to these examples to implement your rule configuration in the project's `config.yaml`.

#### Rule Engine Extension & Field Explanation

- Top-level fields (per rule)
    - `name` (string): Rule name
    - `enabled` (boolean): Whether enabled
    - `priority` (number): Priority, higher executes first
    - `stop_after_match` (boolean): Whether to short-circuit subsequent rules after match
    - `match` (object): Match conditions (AND relationship)
        - `host`: Host regex (case-insensitive, recommended to use ^...$)
        - `path`: Path regex (recommended to start with ^/)
        - `method`: HTTP method (GET/POST/...)
        - `keywords`: Request parameter keywords (single keyword uses string, multiple use array)
    - `request_pipeline` / `response_pipeline` (array): Pipeline actions, execute in order

- Request stage actions (request_pipeline)
    - `set_header`: Set/override request headers (params: { Header: Value })
    - `remove_header`: Remove request headers (params: [Header, ...])
    - `rewrite_url`: Replace URL fragment (params: { from, to })
    - `redirect`: Redirect request (params: "url" or { to: "url" })
    - `replace_body`: Request body string replace (params: { from, to })
    - `set_query_param`: Set/add query parameters (params: { key: value, ... })
    - `set_body_param`: Set/add request body parameters
        - Form: application/x-www-form-urlencoded → { k: v }
        - JSON flat: { a.b: 1, items.0.name: "foo" } (dot path/array index)
        - JSON single key: { path: "a.b", value: 1 } (compatible with to)
        - Auto update Content-Length
    - `set_variable`: Set global variables (support cross-request data sharing)
        - Request stage: Set variables based on request, support built-in variables ({{timestamp}}, {{datetime}}, {{random}})
        - Usage example:
          ```yaml
          # Set request-related variables
          - action: set_variable
            params:
              request_id: "{{timestamp}}"
              request_time: "{{datetime}}"
          ```

- Response stage actions (response_pipeline)
    - `set_status`: Set status code (params: 200)
    - `set_header` / `remove_header`: Set/remove response headers
    - `replace_body`: Response body string replace (params: { from, to })
    - `replace_body_json`: Precisely modify JSON fields
        - Flat direct pass (recommended): Write path keys directly under params: { status: 1, data.id: "abc" }
        - Batch object: { values: { status: 1, data.id: "abc" } }
        - Batch array: { values: [ { path: "status", value: 1 }, ... ] }
        - Single key sugar: { path: "status", value: 1 }
    - `set_variable`: Set global variables (support cross-request data sharing)
        - Response stage: Set variables based on response data, support {{data.field}} format to extract response fields
        - **Important**: `data` is system-created context field wrapping entire response JSON
        - Support built-in variables ({{timestamp}}, {{datetime}}, {{random}}) and global variables
        - Usage example:
          ```yaml
          # Extract data from response
          - action: set_variable
            params:
              user_id: "{{data.user_id}}"
              username: "{{data.username}}"
              auth_token: "{{data.token}}"
              # If response is {"appVersion": "1.2.1"}, use:
              app_version: "{{data.appVersion}}"
          
          # Use in other requests
          - action: replace_body_json
            params:
              values:
                "user_id": "{{user_id}}"
                "username": "{{username}}"
                "timestamp": "{{timestamp}}"
          ```
    - `mock_response`: Completely replace response
        - params: { status_code?, headers?, content? | file?, redirect_to?/location? }
        - headers use "override/add", won't clear other upstream headers
        - file: Read file content (bytes) from disk as response body; relative paths based on cwd, support ~; when Content-Type not explicitly set, try infer from extension (like .json→application/json); response headers append `X-Mocked-From-File: <absolute-path>` for debugging
            - Example:
          ```yaml
          response_pipeline:
            - action: mock_response
              params:
                status_code: 200
                headers: { Cache-Control: no-cache }
                file: mocks/demo.json
          ```
        - redirect_to/location: Default to 302 if status_code not specified, set Location
    - `delay`: Real-time delayed sending
        - params: { time?, jitter?, distribution?, p50?, p95?, p99? } (unit ms)
        - Implementation: Capture flow.reply and delay forwarding; response headers add X-Delay-Applied / X-Delay-Effective
    - `remove_json_field`: Remove fields from JSON response
        - params: { fields: string | array } (field names to delete, support string or array)
        - Support nested field deletion (like "user.metadata")
        - Example:
          ```yaml
          response_pipeline:
            - action: remove_json_field
              params:
                fields: ["password", "token", "debug_info"]
          ```
    - `short_circuit`: Local direct return (equivalent to mock_response)

- Template variable support
    - Built-in variables:
        - `{{timestamp}}`: Current timestamp (seconds)
        - `{{datetime}}`: Current datetime (ISO format)
        - `{{random}}`: Random number (1000-9999)
    - Global variables:
        - `{{variable_name}}`: Global variables set via `set_variable`
        - Support cross-request data sharing, valid during proxy runtime
    - Response data variables:
        - `{{data.field}}`: Extract field value from response JSON
        - **Important**: `data` is system-created context field wrapping entire response data
        - Support nested fields: `{{data.user.profile.name}}`
        - Support array index: `{{data.items.0.title}}`
        - **Example**: If response is `{"appVersion": "1.2.1"}`, use `{{data.appVersion}}` to get "1.2.1"
    - Use cases:
        - Extract response data in `set_variable`: `user_id: "{{data.user_id}}"`
        - Use global variables in `replace_body_json`: `"user_id": "{{user_id}}"`
        - Use timestamp in `set_header`: `X-Request-Time: "{{timestamp}}"`

- Execution & Observability
    - Traverse by priority high to low; after match execute request_pipeline → upstream → response_pipeline
    - `stop_after_match=true`: Don't try subsequent rules after this rule executes
    - Response stage only traverses enabled rules; matched rule name written to response header `X-Rule-Name`

#### More Examples

Replace specific field in response JSON (single key + flat direct pass):

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

Multiple string replacements:

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

302 redirect:

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

Request parameter modification:

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

#### Notes

- Content-Type:
    - replace_body_json only adds application/json; charset=utf-8 when original header is not JSON
    - set_body_param updates Content-Length
- `values` conflict priority:
    - replace_body_json applies flat direct pass first (allows treating `values` as business field name), only parse `values` batch syntax if no modifications, fallback to single key `{ path, value }`
- Disable rules:
    - Rules with enabled=false are skipped in both request and response stages; console loading logs output "loaded N rules (enabled M)"
- Observability headers:
    - Matched rule: X-Rule-Name
    - Delay: X-Delay-Applied / X-Delay-Effective

## Web UI

Access `http://<Your Machine IP>:8002` to view Web UI with features:

- 📊 Real-time traffic statistics
- 📋 Request/response details
- 🔍 Traffic search
- 📈 Performance analysis
- 💾 Data export (/api/export?format=json|jsonl|csv&limit=1000)

## Certificate Management

### Auto Installation

```bash
# After PyPI installation
uproxier cert
# Choose "Install certificate to system"

# From source
python3 -m uproxier cert
# Choose "Install certificate to system"
```

### Manual Installation

⚠️ **Important**: Only install the certificate file, NOT the file containing the private key (`mitmproxy-ca-key.pem` and `mitmproxy-ca.pem`)!

```
# Certificate files stored in user directory
~/.uproxier/                    # User config directory
├── config.yaml                 # Default config file
└── certificates/               # Certificate directory
    ├── mitmproxy-ca-cert.pem   # PEM format certificate (mitmproxy use + user install)
    ├── mitmproxy-ca-key.pem    # Private key file (mitmproxy use, ⚠️ don't install)
    ├── mitmproxy-ca.pem        # Combined cert+key (mitmproxy use, ⚠️ don't install)
    └── mitmproxy-ca-cert.der   # DER format certificate (user install)
```

#### macOS

```bash
# Recommended PEM format (double-click certificate file or command line)
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.uproxier/certificates/mitmproxy-ca-cert.pem

# Or use DER format
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain ~/.uproxier/certificates/mitmproxy-ca-cert.der
```

#### Windows

```bash
# Recommended DER format
certutil -addstore -f ROOT ~/.uproxier/certificates/mitmproxy-ca-cert.der

# Or use PEM format
certutil -addstore -f ROOT ~/.uproxier/certificates/mitmproxy-ca-cert.pem
```

#### Linux

```bash
# Recommended PEM format
sudo cp ~/.uproxier/certificates/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates

# Or use DER format
sudo cp ~/.uproxier/certificates/mitmproxy-ca-cert.der /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

## Project Structure

```
UProxier/
├── requirements.txt    # Dependency list
├── README.md           # GitHub documentation (Chinese)
├── README_EN.md        # GitHub documentation (English)
├── README_PYPI.md      # PyPI documentation
├── API_USAGE.md        # API usage guide
└── uproxier/           # Main package directory
    ├── __init__.py     # Package initialization
    ├── __main__.py     # Module entry point
    ├── cli.py          # Command line tool
    ├── proxy_server.py # Main proxy server
    ├── rules_engine.py # Rule engine
    ├── certificate_manager.py # Certificate management
    ├── web_interface.py # Web UI
    ├── action_processors.py # Action processors
    ├── config_validator.py # Configuration validator
    ├── exceptions.py   # Exception definitions
    ├── utils/           # Utility tools
    ├── version.py      # Version information
    ├── templates/      # Web templates
    └── examples/       # Built-in examples (14 rule examples + config examples)
```

## Troubleshooting

### Common Issues

1. **uproxier command not available after installation**
    ```bash
    # If using pyenv, check version settings
    pyenv versions  # View available versions
    pyenv global    # View current global version
    
    # If global version is not the version where uproxier was installed, set to correct version
    pyenv global 3.10.6  # Replace with your Python version
    
    # If using pyenv, ensure pyenv is properly initialized
    # Add to ~/.zshrc or ~/.bashrc:
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
    echo 'eval "$(pyenv init --path)"' >> ~/.zshrc
    echo 'eval "$(pyenv init -)"' >> ~/.zshrc
    source ~/.zshrc
    
    # Check installation location
    python3 -c "import sys; print(sys.executable.replace('python3', 'uproxier'))"
    
    # If still not available, ensure Python bin directory is in PATH
    export PATH="$(python3 -c "import sys; print(sys.executable.replace('python3', ''))"):$PATH"
    ```

2. **Certificate errors**
     - Ensure certificate is properly installed to system
     - Regenerate certificate: `uproxier cert` (PyPI install) or `python3 -m uproxier cert` (source)

3. **Port already in use**
     - Use different port: `uproxier start --port 8003` (PyPI install) or `python3 -m uproxier start --port 8003` (source)

4. **Rules not taking effect**
     - Check rule configuration correctness
     - Confirm rules are enabled
     - Check log output

5. **HTTPS connection failure**
     - Ensure certificate is installed
     - Check browser proxy settings
     - Try accessing HTTP website to test

### Logs

Enable verbose logging:

```bash
# After PyPI installation
uproxier --verbose start

# From source
python3 -m uproxier --verbose start
```

## License

MIT License

## Contributing

Issues and Pull Requests are welcome!

## Reference

- [mitmproxy](https://mitmproxy.org/)
