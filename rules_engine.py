#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any, DefaultDict

import yaml
from mitmproxy import http

logger = logging.getLogger(__name__)


class Rule:
    """规则基类"""

    def __init__(self, rule_config: Dict[str, Any]):
        self.name = rule_config.get('name', 'unnamed')
        self.enabled = rule_config.get('enabled', True)
        self.priority = rule_config.get('priority', 0)
        match_cfg = rule_config.get('match', {})
        conds: Dict[str, Any] = {}
        if 'host' in match_cfg:
            conds['host_pattern'] = match_cfg['host']
        if 'path' in match_cfg:
            conds['url_pattern'] = match_cfg['path']
        if 'url_pattern' in match_cfg:
            conds['url_pattern'] = match_cfg['url_pattern']
        if 'host_pattern' in match_cfg:
            conds['host_pattern'] = match_cfg['host_pattern']
        if 'method' in match_cfg:
            conds['method'] = match_cfg['method']
        self.match_config = conds
        self.request_pipeline: List[Dict[str, Any]] = rule_config.get('request_pipeline', [])
        self.response_pipeline: List[Dict[str, Any]] = rule_config.get('response_pipeline', [])
        # 命中后是否停止后续规则
        self.stop_after_match = rule_config.get('stop_after_match', False)

        # 预编译匹配器，提升性能
        self._url_re: Optional[re.Pattern] = None
        self._host_re: Optional[re.Pattern] = None
        url_pat = self.match_config.get('url_pattern')
        host_pat = self.match_config.get('host_pattern')
        # 如果来自 match.path 或者以 ^/ 开头，优先对 request.path 进行匹配
        self._use_path: bool = False
        if isinstance(url_pat, str) and url_pat.startswith('^/'):
            self._use_path = True
        try:
            if isinstance(url_pat, str):
                self._url_re = re.compile(url_pat)
        except re.error:
            logger.warning(f"规则 {self.name} 的 url_pattern 无效: {url_pat}")
        try:
            if isinstance(host_pat, str):
                self._host_re = re.compile(host_pat, re.IGNORECASE)
        except re.error:
            logger.warning(f"规则 {self.name} 的 host_pattern 无效: {host_pat}")

        # 提取可能的 host 精确键与 path 前缀键（用于索引快速筛选）
        self._host_key: Optional[str] = None
        if isinstance(host_pat, str):
            # 形如 ^example\.com$ 视为精确 host
            if host_pat.startswith('^') and host_pat.endswith('$'):
                literal = host_pat[1:-1]
                if '\\' in literal:
                    literal = literal.replace('\\.', '.')
                # 简单启发：若不含正则元字符，则作为 host key
                if re.match(r'^[A-Za-z0-9_.:-]+$', literal):
                    self._host_key = literal.lower()

        self._path_prefix: Optional[str] = None
        if isinstance(url_pat, str) and url_pat.startswith('^/'):
            # 截到第一个正则元字符前（在去掉^后的字符串上匹配）
            m = re.match(r'^/[^.*+?^${}()|\\\[\]\s]*', url_pat[1:])
            if m:
                prefix = m.group(0)
                self._path_prefix = prefix if prefix.startswith('/') else '/' + prefix

    def match(self, request: http.Request) -> bool:
        """检查请求是否匹配规则"""
        if not self.enabled:
            return False

        # 检查 URL/Path 匹配
        if self._url_re is not None:
            target = self._select_url_target(request)
            if not self._url_re.search(target):
                return False

        # 检查主机匹配
        if self._host_re is not None:
            if not self._host_re.search(request.pretty_host):
                return False

        # 检查方法匹配
        if 'method' in self.match_config:
            if request.method.upper() != self.match_config['method'].upper():
                return False

        # 检查头部匹配
        if 'headers' in self.match_config:
            for header_name, header_value in self.match_config['headers'].items():
                if header_name not in request.headers:
                    return False
                if isinstance(header_value, str):
                    if header_value not in request.headers[header_name]:
                        return False
                elif isinstance(header_value, dict):
                    if 'pattern' in header_value:
                        if not re.search(header_value['pattern'], request.headers[header_name]):
                            return False

        return True

    def _select_url_target(self, request: http.Request) -> str:
        """选择用于 URL 正则匹配的字符串（path 优先或完整 URL）。"""
        try:
            if self._use_path and hasattr(request, 'path'):
                return request.path
            return request.pretty_url
        except Exception:
            return getattr(request, 'path', getattr(request, 'pretty_url', ''))

    def apply_request_actions(self, request: http.Request) -> Optional[http.Request]:
        """应用请求动作（仅通用 DSL 的 request_pipeline）"""
        modified = False

        for step in self.request_pipeline:
            action = step.get('action')
            params = step.get('params', {})
            if action == 'set_header':
                for k, v in params.items():
                    request.headers[k] = v
                    modified = True
            elif action == 'remove_header':
                keys = params if isinstance(params, list) else []
                for k in keys:
                    if k in request.headers:
                        del request.headers[k]
                        modified = True
            elif action == 'rewrite_url':
                _from = params.get('from', '')
                _to = params.get('to', '')
                if _from:
                    request.url = request.url.replace(_from, _to)
                    modified = True
            elif action == 'redirect':
                to = params if isinstance(params, str) else params.get('to')
                if to:
                    request.url = to
                    modified = True
            elif action == 'replace_body':
                if request.content:
                    src = params.get('from', '')
                    dst = params.get('to', '')
                    try:
                        content = request.content.decode('utf-8', errors='ignore')
                        request.content = content.replace(src, dst).encode('utf-8')
                        modified = True
                    except Exception:
                        pass
            elif action == 'set_query_param':
                # params: { key: value, ... }
                try:
                    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
                    url = request.url
                    parsed = urlparse(url)
                    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                    for k, v in (params or {}).items():
                        q[str(k)] = str(v)
                    new_query = urlencode(q, doseq=False)
                    request.url = urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    modified = True
                except Exception:
                    pass
            elif action == 'set_body_param':
                # 支持 application/x-www-form-urlencoded 与 application/json（含数组/嵌套路径 key.a.b 或 0.properties.x）
                try:
                    ctype = request.headers.get('content-type', '').lower()
                    if 'application/x-www-form-urlencoded' in ctype:
                        from urllib.parse import parse_qsl, urlencode
                        body = request.content.decode('utf-8', errors='ignore') if request.content else ''
                        kv = dict(parse_qsl(body, keep_blank_values=True))
                        for k, v in (params or {}).items():
                            kv[str(k)] = str(v)
                        request.content = urlencode(kv).encode('utf-8')
                        request.headers['Content-Length'] = str(len(request.content))
                        modified = True
                    elif 'application/json' in ctype:
                        import json as _json
                        try:
                            obj = _json.loads(
                                request.content.decode('utf-8', errors='ignore') or '{}') if request.content else {}
                        except Exception:
                            obj = {}

                        def _set_deep(container, key_path, value):
                            keys = str(key_path).split('.')
                            cur = container
                            for i, key in enumerate(keys):
                                is_last = (i == len(keys) - 1)
                                if isinstance(cur, list):
                                    try:
                                        idx = int(key)
                                    except Exception:
                                        return
                                    if idx < 0 or idx >= len(cur):
                                        return
                                    if is_last:
                                        cur[idx] = value
                                    else:
                                        if not isinstance(cur[idx], (dict, list)):
                                            return
                                        cur = cur[idx]
                                else:
                                    if is_last:
                                        cur[key] = value
                                    else:
                                        if key not in cur or not isinstance(cur[key], (dict, list)):
                                            cur[key] = {}
                                        cur = cur[key]

                        def _apply_params_to(target):
                            for k, v in (params or {}).items():
                                if isinstance(target, (dict, list)):
                                    _set_deep(target, k, v)

                        if isinstance(obj, list):
                            for item in obj:
                                _apply_params_to(item)
                        elif isinstance(obj, dict):
                            _apply_params_to(obj)
                        request.content = _json.dumps(obj, ensure_ascii=False).encode('utf-8')
                        request.headers['Content-Length'] = str(len(request.content))
                        modified = True
                except Exception:
                    pass
            elif action == 'short_circuit':
                # 请求阶段短路：在 request 对象上挂载预构造的响应，供上层捕获并直接返回
                try:
                    sc = params or {}
                    status_code = int(sc.get('status') if 'status' in sc else sc.get('status_code', 200))
                    hdrs = sc.get('headers') or {}
                    content = sc.get('content')
                    body: bytes = b''
                    if content is not None:
                        if isinstance(content, dict):
                            body = json.dumps(content, ensure_ascii=False).encode('utf-8')
                            if 'Content-Type' not in hdrs:
                                hdrs['Content-Type'] = 'application/json; charset=utf-8'
                        elif isinstance(content, str):
                            body = content.encode('utf-8')
                            if 'Content-Type' not in hdrs:
                                hdrs['Content-Type'] = 'text/plain; charset=utf-8'
                        else:
                            body = str(content).encode('utf-8')
                    response = http.Response.make(status_code, body, hdrs)
                    setattr(request, 'short_circuit_response', response)
                    modified = True
                except Exception:
                    pass
        return request if modified else None

    def apply_response_actions(self, response: http.Response) -> Optional[http.Response]:
        """应用响应动作（仅通用 DSL 的 response_pipeline）"""
        modified = False
        for step in self.response_pipeline:
            action = step.get('action')
            params = step.get('params', {})
            if action == 'set_status':
                try:
                    response.status_code = int(params)
                    modified = True
                except Exception:
                    pass
            elif action == 'set_header':
                for k, v in params.items():
                    response.headers[k] = v
                    modified = True
            elif action == 'remove_header':
                keys = params if isinstance(params, list) else []
                for k in keys:
                    if k in response.headers:
                        del response.headers[k]
                        modified = True
            elif action == 'replace_body':
                if response.content:
                    src = params.get('from', '')
                    dst = params.get('to', '')
                    try:
                        content = response.content.decode('utf-8', errors='ignore')
                        response.content = content.replace(src, dst).encode('utf-8')
                        modified = True
                    except Exception:
                        pass
            elif action == 'replace_body_json':
                # 精确修改 JSON 内某路径的值：
                # 支持三种写法：
                # 1) 单个: { path: 'a.b.c', value: <v> }
                # 2) 批量(values: 对象): { values: { 'a.b': 1, 'x.y': 'ok' } }
                # 3) 批量(values: 数组): { values: [ { path: 'a.b', value: 1 }, { path: 'x.y', value: 'ok' } ] }
                try:
                    import json as _json
                    obj = _json.loads(
                        response.content.decode('utf-8', errors='ignore') or 'null') if response.content else None

                    def _set_deep(container, key_path, value):
                        keys = str(key_path).split('.')
                        cur = container
                        for i, key in enumerate(keys):
                            is_last = (i == len(keys) - 1)
                            if isinstance(cur, list):
                                try:
                                    idx = int(key)
                                except Exception:
                                    return False
                                if idx < 0 or idx >= len(cur):
                                    return False
                                if is_last:
                                    cur[idx] = value
                                    return True
                                if not isinstance(cur[idx], (dict, list)):
                                    return False
                                cur = cur[idx]
                            elif isinstance(cur, dict):
                                if is_last:
                                    cur[key] = value
                                    return True
                                if key not in cur or not isinstance(cur[key], (dict, list)):
                                    cur[key] = {}
                                cur = cur[key]
                            else:
                                return False

                    def _apply_single(pth, val):
                        if obj is None:
                            return False
                        return _set_deep(obj, pth, val)

                    did_modify = False
                    # 1) 扁平直传优先：允许将 'values' 当作普通路径键使用（避免歧义）
                    if isinstance(params, dict):
                        reserved = {'path', 'value', 'to'}  # 不排除 'values'
                        flat_pairs = {k: v for k, v in params.items() if k not in reserved}
                        if flat_pairs:
                            for kp, vv in flat_pairs.items():
                                if _apply_single(kp, vv):
                                    did_modify = True
                    # 2) 若没有扁平键，再看批量 values 语法
                    if not did_modify and isinstance(params, dict) and 'values' in params:
                        vals = params.get('values')
                        if isinstance(vals, dict):
                            for kp, vv in vals.items():
                                if _apply_single(kp, vv):
                                    did_modify = True
                        elif isinstance(vals, list):
                            for ent in vals:
                                if isinstance(ent, dict) and 'path' in ent and ('value' in ent or 'to' in ent):
                                    vv = ent['value'] if 'value' in ent else ent.get('to')
                                    if _apply_single(ent['path'], vv):
                                        did_modify = True
                    # 3) 最后回退到单键语法糖
                    if not did_modify:
                        path = params.get('path')
                        to_val = params.get('value') if isinstance(params, dict) and 'value' in params else params.get(
                            'to')
                        if path is not None:
                            if _apply_single(path, to_val):
                                did_modify = True

                    if did_modify:
                        response.content = _json.dumps(obj, ensure_ascii=False).encode('utf-8')
                        try:
                            ct = response.headers.get('Content-Type', '')
                            if 'application/json' not in ct.lower():
                                response.headers['Content-Type'] = 'application/json; charset=utf-8'
                        except Exception:
                            response.headers['Content-Type'] = 'application/json; charset=utf-8'
                        modified = True
                except Exception:
                    pass
            elif action == 'mock_response':
                mock = params or {}
                # 直接设置状态码/头/体
                if 'status_code' in mock:
                    response.status_code = mock.get('status_code', 200)
                # 便捷重定向：支持 redirect_to/location 字段
                if 'redirect_to' in mock and mock.get('redirect_to'):
                    # 若未显式指定状态码，则默认 302
                    if 'status_code' not in mock:
                        response.status_code = 302
                    response.headers['Location'] = str(mock['redirect_to'])
                if 'location' in mock and mock.get('location'):
                    if 'status_code' not in mock:
                        response.status_code = 302
                    response.headers['Location'] = str(mock['location'])
                if 'headers' in mock:
                    # 不清空原有头，逐项覆盖/新增指定键
                    for hk, hv in mock['headers'].items():
                        response.headers[hk] = hv
                if 'file' in mock:
                    try:
                        p = Path(mock['file']).expanduser()
                        if not p.is_absolute():
                            p = Path.cwd() / p
                        data = p.read_bytes()
                        response.content = data
                    except Exception as e:
                        response.status_code = 500
                        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
                        response.content = f"Mock file read error: {e}".encode('utf-8')
                elif 'content' in mock:
                    content = mock['content']
                    if isinstance(content, dict):
                        response.headers['Content-Type'] = 'application/json; charset=utf-8'
                        response.content = json.dumps(content, ensure_ascii=False).encode('utf-8')
                    elif isinstance(content, str):
                        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
                        response.content = content.encode('utf-8')
                    else:
                        response.content = str(content).encode('utf-8')
                modified = True
            elif action == 'delay':
                delay_cfg = params or {}
                if 'time' in delay_cfg:
                    response.headers['X-Delay-Time'] = str(int(delay_cfg.get('time', 0)))
                if 'jitter' in delay_cfg:
                    response.headers['X-Delay-Jitter'] = str(int(delay_cfg.get('jitter', 0)))
                if 'distribution' in delay_cfg:
                    response.headers['X-Delay-Distrib'] = str(delay_cfg.get('distribution'))
                for k in ('p50', 'p95', 'p99'):
                    if k in delay_cfg:
                        response.headers[f"X-Delay-{k.upper()}"] = str(int(delay_cfg[k]))
                modified = True
            elif action == 'conditional':
                cond = params or {}
                when = cond.get('when') or {}
                then_steps = cond.get('then') or []
                else_steps = cond.get('else') or []

                def _match_cond(rsp: http.Response, spec: Dict[str, Any]) -> bool:
                    try:
                        if 'status_code' in spec and rsp.status_code != int(spec['status_code']):
                            return False
                        if 'headers' in spec:
                            for hk, hv in (spec.get('headers') or {}).items():
                                if hk not in rsp.headers or rsp.headers[hk] != hv:
                                    return False
                        if 'content_contains' in spec:
                            body = rsp.content.decode('utf-8', errors='ignore') if rsp.content else ''
                            if str(spec['content_contains']) not in body:
                                return False
                        return True
                    except Exception:
                        return False

                branch = then_steps if _match_cond(response, when) else else_steps
                # 递归执行分支中的动作
                for step2 in branch:
                    if not isinstance(step2, dict):
                        continue
                    act2 = step2.get('action')
                    par2 = step2.get('params', {})
                    tmp_rule = Rule(
                        {'match': {}, 'request_pipeline': [], 'response_pipeline': [{'action': act2, 'params': par2}]})
                    tmp_rule.enabled = True
                    tmp_resp = tmp_rule.apply_response_actions(response)
                    if tmp_resp is not None:
                        response = tmp_resp
                        modified = True
            elif action == 'short_circuit':
                mock = {'status_code': params.get('status', 200)}
                if 'headers' in params:
                    mock['headers'] = params['headers']
                if 'content' in params:
                    mock['content'] = params['content']
                # 递归调用自身处理 mock
                tmp_rule = {'match': {}, 'request_pipeline': [],
                            'response_pipeline': [{'action': 'mock_response', 'params': mock}]}
                temp = Rule(tmp_rule)
                temp.enabled = True
                tmp_resp = temp.apply_response_actions(response)
                if tmp_resp is not None:
                    response = tmp_resp
                    modified = True
        return response if modified else None

    def _check_conditional_match(self, condition: Dict[str, Any], response: http.Response) -> bool:
        """检查条件是否匹配"""
        # 检查状态码条件
        if 'status_code' in condition:
            if response.status_code != condition['status_code']:
                return False

        # 检查头部条件
        if 'headers' in condition:
            for header_name, header_value in condition['headers'].items():
                if header_name not in response.headers:
                    return False
                if response.headers[header_name] != header_value:
                    return False

        # 检查内容条件
        if 'content_contains' in condition:
            content = response.content.decode('utf-8', errors='ignore')
            if condition['content_contains'] not in content:
                return False

        return True


class RulesEngine:
    """规则引擎"""

    def __init__(self, config_path: str = "config.yaml", silent: bool = False):
        self.config_path = config_path
        self.silent = silent
        self.rules: List[Rule] = []
        self.load_rules()

    def load_rules(self):
        """从配置文件加载规则"""
        try:
            config_path = Path(self.config_path)
            if not config_path.exists():
                self.create_default_config()

            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            self.rules = []
            for idx, rule_config in enumerate(config.get('rules', [])):
                self._validate_rule_config(rule_config, idx)
                rule = Rule(rule_config)
                self.rules.append(rule)

            # 按优先级排序
            self.rules.sort(key=lambda x: x.priority, reverse=True)

            # 构建索引：host_key -> [Rule]，path_prefix -> [Rule]，以及通用列表
            self._host_index: DefaultDict[str, List[Rule]] = defaultdict(list)
            self._path_index: DefaultDict[str, List[Rule]] = defaultdict(list)
            self._generic_rules: List[Rule] = []

            for r in self.rules:
                inserted = False
                if getattr(r, '_host_key', None):
                    self._host_index[r._host_key].append(r)
                    inserted = True
                if getattr(r, '_path_prefix', None):
                    self._path_index[r._path_prefix].append(r)
                    inserted = True
                if not inserted:
                    self._generic_rules.append(r)

            if not self.silent:
                enabled_count = sum(1 for r in self.rules if getattr(r, 'enabled', True))
                logger.info(f"加载了 {len(self.rules)} 条规则（启用 {enabled_count} 条）")

        except Exception as e:
            if not self.silent:
                logger.error(f"加载规则失败: {e}")
            self.rules = []

    def create_default_config(self):
        """创建默认配置文件"""
        default_config = {
            'rules': [
                {
                    'name': '示例规则 - 修改 User-Agent',
                    'enabled': False,
                    'priority': 1,
                    'match': {'host': r'example\.com'},
                    'request_pipeline': [
                        {'action': 'set_header', 'params': {'User-Agent': 'Custom-Proxy-Agent/1.0'}}
                    ],
                    'response_pipeline': []
                }
            ]
        }

        config_path = Path(self.config_path)
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)

        if not self.silent:
            logger.info(f"创建默认配置文件: {self.config_path}")

    def reload_rules(self):
        """重新加载规则"""
        self.load_rules()

    def add_rule(self, rule_config: Dict[str, Any]):
        """添加新规则"""
        rule = Rule(rule_config)
        self.rules.append(rule)
        self.rules.sort(key=lambda x: x.priority, reverse=True)
        self.save_rules()

    def remove_rule(self, rule_name: str):
        """删除规则"""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
        self.save_rules()

    def enable_rule(self, rule_name: str, enabled: bool = True):
        """启用/禁用规则"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = enabled
                break
        self.save_rules()

    def save_rules(self):
        """保存规则到配置文件"""
        try:
            def _export_match(conds: Dict[str, Any]) -> Dict[str, Any]:
                # 将内部 match_config(host_pattern/url_pattern/method) 回写为 DSL 的 match(host/path/method)
                out: Dict[str, Any] = {}
                hp = conds.get('host_pattern')
                up = conds.get('url_pattern')
                if isinstance(hp, str):
                    out['host'] = hp
                if isinstance(up, str):
                    # 以 ^/ 开头视为 path 正则，否则也回写为 path（保持 README 一致）
                    out['path'] = up
                m = conds.get('method')
                if isinstance(m, str):
                    out['method'] = m
                return out

            config = {
                'rules': [
                    {
                        'name': rule.name,
                        'enabled': rule.enabled,
                        'priority': rule.priority,
                        'stop_after_match': getattr(rule, 'stop_after_match', False),
                        'match': _export_match(getattr(rule, 'match_config', {}) or {}),
                        'request_pipeline': getattr(rule, 'request_pipeline', []),
                        'response_pipeline': getattr(rule, 'response_pipeline', [])
                    }
                    for rule in self.rules
                ]
            }

            config_path = Path(self.config_path)
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

            if not self.silent:
                logger.info("规则已保存")

        except Exception as e:
            if not self.silent:
                logger.error(f"保存规则失败: {e}")

    def _validate_rule_config(self, rule_config: Dict[str, Any], idx: int) -> None:
        name = rule_config.get('name', f'rule_{idx}')

        allowed_top = {'name', 'enabled', 'priority', 'stop_after_match', 'match', 'request_pipeline',
                       'response_pipeline'}
        unknown = set(rule_config.keys()) - allowed_top
        if unknown:
            raise ValueError(f"规则 '{name}' 存在不支持的顶层字段: {sorted(list(unknown))}")
        match = rule_config.get('match', {})
        if not isinstance(match, dict):
            raise ValueError(f"规则 '{name}' 的 match 必须为对象")
        for key in ('request_pipeline', 'response_pipeline'):
            pipeline = rule_config.get(key, [])
            if pipeline is None:
                continue
            if not isinstance(pipeline, list):
                raise ValueError(f"规则 '{name}' 的 {key} 必须为数组")
            for i, step in enumerate(pipeline):
                if not isinstance(step, dict):
                    raise ValueError(f"规则 '{name}' 的 {key}[{i}] 必须为对象")
                if 'action' not in step:
                    raise ValueError(f"规则 '{name}' 的 {key}[{i}] 缺少 action 字段")
                action = step.get('action')
                params = step.get('params', {})
                if params is not None and not isinstance(params, (dict, str, int, float, list)):
                    raise ValueError(f"规则 '{name}' 的 {key}[{i}].params 类型不支持")
                req_actions = {'set_header', 'remove_header', 'rewrite_url', 'redirect', 'replace_body',
                               'short_circuit', 'set_query_param', 'set_body_param'}
                res_actions = {'set_status', 'set_header', 'remove_header', 'replace_body', 'replace_body_json',
                               'mock_response', 'delay', 'short_circuit', 'conditional'}
                valid = req_actions if key == 'request_pipeline' else res_actions
                if action not in valid:
                    raise ValueError(f"规则 '{name}' 的 {key}[{i}].action 不支持: {action}")

    def apply_request_rules(self, request: http.Request) -> Optional[http.Request]:
        """应用请求规则，支持命中后停止(stop_after_match)与多规则叠加"""
        candidates: List[Rule] = []
        host_l = request.pretty_host.lower() if hasattr(request, 'pretty_host') else ''
        path = request.path if hasattr(request, 'path') else ''
        # host 命中
        if hasattr(self, '_host_index') and host_l in self._host_index:
            candidates.extend(self._host_index[host_l])

        if hasattr(self, '_path_index'):
            for prefix, rules in self._path_index.items():
                if path.startswith(prefix):
                    candidates.extend(rules)
        candidates.extend(getattr(self, '_generic_rules', []))

        # 去重并保持优先级（按 self.rules 排序）
        seen = set()
        ordered = []
        for r in self.rules:
            if r in candidates and id(r) not in seen:
                ordered.append(r)
                seen.add(id(r))

        result_request: Optional[http.Request] = None
        for rule in ordered:
            if rule.match(request):
                if not self.silent:
                    logger.debug(f"应用请求规则: {rule.name}")
                modified_request = rule.apply_request_actions(request)
                if modified_request is not None:
                    result_request = modified_request
                    if getattr(rule, 'stop_after_match', False):
                        break
        return result_request

    def apply_response_rules(self, response: http.Response) -> Optional[http.Response]:
        """应用响应规则，支持命中后停止(stop_after_match)与多规则叠加"""
        # 为避免索引筛选遗漏，响应阶段使用全量规则表按优先级遍历，再用 rule.match(response.request) 过滤
        ordered = list(self.rules)

        result_response: Optional[http.Response] = None
        for rule in ordered:
            try:
                if not getattr(rule, 'enabled', True):
                    continue
                req = response.request if hasattr(response, 'request') else None
                if req is None:
                    continue
                if not rule.match(req):
                    continue
            except Exception:
                continue
            modified_response = rule.apply_response_actions(response)
            if modified_response is not None:
                try:
                    existing = modified_response.headers.get('X-Rule-Name') or ''
                    if existing:
                        if rule.name not in [s.strip() for s in existing.split(',')]:
                            modified_response.headers['X-Rule-Name'] = existing + ',' + rule.name
                    else:
                        modified_response.headers['X-Rule-Name'] = rule.name
                except Exception:
                    pass
                result_response = modified_response
                if getattr(rule, 'stop_after_match', False):
                    break
        return result_response

    def get_rules(self) -> List[Dict[str, Any]]:
        """获取所有规则"""
        result: List[Dict[str, Any]] = []
        for rule in self.rules:
            result.append({
                'name': rule.name,
                'enabled': rule.enabled,
                'priority': rule.priority,
                'stop_after_match': getattr(rule, 'stop_after_match', False),
                'match': getattr(rule, 'match_config', {}),
                'request_pipeline': getattr(rule, 'request_pipeline', []),
                'response_pipeline': getattr(rule, 'response_pipeline', []),
            })
        return result
