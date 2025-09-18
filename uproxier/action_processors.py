#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import mitmproxy.http as http


class ActionProcessor(ABC):
    """动作处理器基类"""

    @property
    @abstractmethod
    def action_name(self) -> str:
        """返回动作名称"""
        pass

    @abstractmethod
    def can_handle(self, action: str) -> bool:
        """判断是否能处理指定的动作"""
        pass

    @abstractmethod
    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """
        处理请求阶段的动作
        Args:
            request: HTTP 请求对象
            params: 动作参数
        Returns:
            bool: 是否修改了请求
        """
        pass

    @abstractmethod
    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """
        处理响应阶段的动作
        Args:
            response: HTTP 响应对象
            params: 动作参数
        Returns:
            bool: 是否修改了响应
        """
        pass


class SetHeaderProcessor(ActionProcessor):
    """设置请求头/响应头处理器"""

    @property
    def action_name(self) -> str:
        return 'set_header'

    def can_handle(self, action: str) -> bool:
        return action == 'set_header'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """设置请求头"""
        modified = False
        for k, v in (params or {}).items():
            request.headers[k] = v
            modified = True
        return modified

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """设置响应头"""
        modified = False
        for k, v in (params or {}).items():
            response.headers[k] = v
            modified = True
        return modified


class RemoveHeaderProcessor(ActionProcessor):
    """移除请求头/响应头处理器"""

    @property
    def action_name(self) -> str:
        return 'remove_header'

    def can_handle(self, action: str) -> bool:
        return action == 'remove_header'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """移除请求头"""
        modified = False
        keys = params if isinstance(params, list) else []
        for k in keys:
            if k in request.headers:
                del request.headers[k]
                modified = True
        return modified

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """移除响应头"""
        modified = False
        keys = params if isinstance(params, list) else []
        for k in keys:
            if k in response.headers:
                del response.headers[k]
                modified = True
        return modified


class RewriteUrlProcessor(ActionProcessor):
    """URL 重写处理器"""

    @property
    def action_name(self) -> str:
        return 'rewrite_url'

    def can_handle(self, action: str) -> bool:
        return action == 'rewrite_url'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """重写请求 URL"""
        params = params or {}
        _from = params.get('from', '')
        _to = params.get('to', '')
        if _from and _to:
            request.url = request.url.replace(_from, _to)
            return True
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """响应阶段不支持 URL 重写"""
        return False


class RedirectProcessor(ActionProcessor):
    """重定向处理器"""

    @property
    def action_name(self) -> str:
        return 'redirect'

    def can_handle(self, action: str) -> bool:
        return action == 'redirect'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """重定向请求"""
        if params is None:
            return False
        if isinstance(params, str):
            to = params
        elif isinstance(params, dict):
            to = params.get('to')
        else:
            return False
        if to:
            request.url = to
            return True
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """响应阶段不支持重定向"""
        return False


class ReplaceBodyProcessor(ActionProcessor):
    """替换请求体/响应体处理器"""

    @property
    def action_name(self) -> str:
        return 'replace_body'

    def can_handle(self, action: str) -> bool:
        return action == 'replace_body'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """替换请求体"""
        if not request.content:
            return False

        params = params or {}
        src = params.get('from', '')
        dst = params.get('to', '')
        if not src:
            return False

        try:
            content = request.content.decode('utf-8', errors='ignore')
            request.content = content.replace(src, dst).encode('utf-8')
            return True
        except Exception:
            return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """替换响应体"""
        if not response.content:
            return False

        params = params or {}
        src = params.get('from', '')
        dst = params.get('to', '')
        if not src:
            return False

        try:
            content = response.content.decode('utf-8', errors='ignore')
            response.content = content.replace(src, dst).encode('utf-8')
            return True
        except Exception:
            return False


class SetQueryParamProcessor(ActionProcessor):
    """设置查询参数处理器"""

    @property
    def action_name(self) -> str:
        return 'set_query_param'

    def can_handle(self, action: str) -> bool:
        return action == 'set_query_param'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """设置查询参数"""
        try:
            url = request.url
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))

            for k, v in (params or {}).items():
                q[k] = str(v)

            new_query = urlencode(q, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            request.url = new_url
            return True
        except Exception:
            return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """响应阶段不支持设置查询参数"""
        return False


class SetBodyParamProcessor(ActionProcessor):
    """设置请求体参数处理器"""

    @property
    def action_name(self) -> str:
        return 'set_body_param'

    def can_handle(self, action: str) -> bool:
        return action == 'set_body_param'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """设置请求体参数"""
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
                return True
            elif 'application/json' in ctype:
                import json as _json
                try:
                    obj = _json.loads(
                        request.content.decode('utf-8', errors='ignore') or '{}') if request.content else {}
                except Exception:
                    obj = {}

                def _set_deep(container: Any, key_path: str, value: Any) -> None:
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

                def _apply_params_to(target: Any) -> None:
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
                return True
            return False
        except Exception:
            return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """响应阶段不支持设置请求体参数"""
        return False


class SetStatusProcessor(ActionProcessor):
    """设置响应状态码处理器"""

    @property
    def action_name(self) -> str:
        return 'set_status'

    def can_handle(self, action: str) -> bool:
        return action == 'set_status'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段不支持设置状态码"""
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """设置响应状态码"""
        try:
            status_code = params if isinstance(params, (int, str)) else params.get('status_code', params)
            response.status_code = int(status_code)
            return True
        except Exception:
            return False


class ReplaceBodyJsonProcessor(ActionProcessor):
    """替换 JSON 响应体处理器"""

    @property
    def action_name(self) -> str:
        return 'replace_body_json'

    def can_handle(self, action: str) -> bool:
        return action == 'replace_body_json'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段不支持 JSON 替换"""
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """替换 JSON 响应体"""
        if not response.content:
            return False

        try:
            params = params or {}
            obj = json.loads(response.content.decode('utf-8', errors='ignore') or 'null')

            def _set_deep(container: Any, key_path: str, value: Any) -> None:
                keys = str(key_path).split('.')
                current = container
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = value

            # 处理单个路径
            if 'path' in params and 'value' in params:
                _set_deep(obj, params['path'], params['value'])

            # 处理批量修改
            elif 'values' in params:
                values = params['values']
                if isinstance(values, dict):
                    for path, value in values.items():
                        _set_deep(obj, path, value)
                elif isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict) and 'path' in item and 'value' in item:
                            _set_deep(obj, item['path'], item['value'])

            response.content = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            return True
        except Exception:
            return False


class MockResponseProcessor(ActionProcessor):
    """模拟响应处理器"""

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir

    @property
    def action_name(self) -> str:
        return 'mock_response'

    def can_handle(self, action: str) -> bool:
        return action == 'mock_response'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段不支持模拟响应"""
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """模拟响应"""
        mock = params or {}

        # 设置状态码
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

        # 设置响应头
        if 'headers' in mock:
            # 不清空原有头，逐项覆盖/新增指定键
            for hk, hv in mock['headers'].items():
                response.headers[hk] = hv

        # 处理文件内容
        if 'file' in mock:
            try:
                p = Path(mock['file']).expanduser()
                if not p.is_absolute():
                    # 相对于配置文件目录
                    if self.config_dir:
                        p = (Path(self.config_dir) / p).resolve()
                    else:
                        # 回退到当前工作目录（向后兼容）
                        p = (Path.cwd() / p).resolve()
                data = p.read_bytes()
                response.content = data
            except Exception as e:
                response.status_code = 500
                response.headers['Content-Type'] = 'text/plain; charset=utf-8'
                response.content = f"Mock file read error: {e}".encode('utf-8')
        # 处理直接内容
        elif 'content' in mock:
            content = mock['content']
            if isinstance(content, dict):
                # 只有在没有设置 Content-Type 时才自动设置
                if 'Content-Type' not in mock.get('headers', {}):
                    response.headers['Content-Type'] = 'application/json; charset=utf-8'
                response.content = json.dumps(content, ensure_ascii=False).encode('utf-8')
            elif isinstance(content, str):
                # 只有在没有设置 Content-Type 时才自动设置
                if 'Content-Type' not in mock.get('headers', {}):
                    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
                response.content = content.encode('utf-8')
            else:
                response.content = str(content).encode('utf-8')

        return True


class DelayProcessor(ActionProcessor):
    """延迟处理器"""

    @property
    def action_name(self) -> str:
        return 'delay'

    def can_handle(self, action: str) -> bool:
        return action == 'delay'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段不支持延迟"""
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """延迟响应"""
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
        return True


class ShortCircuitProcessor(ActionProcessor):
    """短路处理器"""

    @property
    def action_name(self) -> str:
        return 'short_circuit'

    def can_handle(self, action: str) -> bool:
        return action == 'short_circuit'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段短路：在 request 对象上挂载预构造的响应，供上层捕获并直接返回"""
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
            return True
        except Exception:
            return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """响应阶段短路"""
        params = params or {}
        mock = {'status_code': params.get('status', 200)}
        if 'headers' in params:
            mock['headers'] = params['headers']
        if 'content' in params:
            mock['content'] = params['content']
        mock_processor = MockResponseProcessor()
        if mock_processor.process_response(response, mock):
            return True
        return False


class ConditionalProcessor(ActionProcessor):
    """条件处理器"""

    def __init__(self, manager=None):
        self.manager = manager

    @property
    def action_name(self) -> str:
        return 'conditional'

    def can_handle(self, action: str) -> bool:
        return action == 'conditional'

    def process_request(self, request: http.Request, params: Dict[str, Any]) -> bool:
        """请求阶段不支持条件处理"""
        return False

    def process_response(self, response: http.Response, params: Dict[str, Any]) -> bool:
        """条件处理"""
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
        modified = False
        for step2 in branch:
            if not isinstance(step2, dict):
                continue
            act2 = step2.get('action')
            par2 = step2.get('params', {})
            # 直接调用对应的处理器
            if self.manager:
                processor = self.manager.get_processor(act2)
                if processor and processor.process_response(response, par2):
                    modified = True
        return modified


class ActionProcessorManager:
    """动作处理器管理器"""

    def __init__(self, config_dir: Optional[str] = None):
        self._processors: List[ActionProcessor] = []
        self.config_dir = config_dir
        self._register_default_processors()

    def _register_default_processors(self) -> None:
        """注册默认的处理器"""
        self._processors.extend([
            SetHeaderProcessor(),
            RemoveHeaderProcessor(),
            RewriteUrlProcessor(),
            RedirectProcessor(),
            ReplaceBodyProcessor(),
            SetQueryParamProcessor(),
            SetBodyParamProcessor(),
            SetStatusProcessor(),
            ReplaceBodyJsonProcessor(),
            MockResponseProcessor(self.config_dir),
            DelayProcessor(),
            ShortCircuitProcessor(),
            ConditionalProcessor(self)
        ])

    def register_processor(self, processor: ActionProcessor) -> None:
        """注册新的处理器"""
        self._processors.append(processor)

    def get_processor(self, action: str) -> Optional[ActionProcessor]:
        """获取指定动作的处理器"""
        for processor in self._processors:
            if processor.can_handle(action):
                return processor
        return None

    def process_request_action(self, action: str, request: http.Request,
                               params: Dict[str, Any]) -> bool:
        """处理请求阶段的动作"""
        processor = self.get_processor(action)
        if processor:
            return processor.process_request(request, params)
        return False

    def process_response_action(self, action: str, response: http.Response,
                                params: Dict[str, Any]) -> bool:
        """处理响应阶段的动作"""
        processor = self.get_processor(action)
        if processor:
            return processor.process_response(response, params)
        return False
