#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import logging
import pathlib
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

from mitmproxy import http
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from certificate_manager import CertificateManager
from rules_engine import RulesEngine
from web_interface import WebInterface

logger = logging.getLogger(__name__)


class ProxyAddon:
    """代理服务器插件，处理请求和响应"""

    def __init__(self, rules_engine: RulesEngine, web_interface: WebInterface, save_path: Optional[str] = None,
                 save_format: str = 'jsonl', silent: bool = False, config_path: Optional[str] = None):
        self.rules_engine = rules_engine
        self.web_interface = web_interface
        self.silent = silent
        self.request_count = 0
        self.traffic_data = []
        self.save_format = save_format
        self.save_path = None
        self.internal_targets = set()
        self.internal_web_ports = set()
        self.config_path = config_path or "config.yaml"
        if save_path:
            p = pathlib.Path(save_path)
            if p.is_dir():
                p = p / 'traffic.jsonl'
            p.parent.mkdir(parents=True, exist_ok=True)
            self.save_path = str(p)

        # 读取抓包配置
        self.capture_config = self._load_capture_config()
        # 预编译 include/exclude 过滤器
        self._compile_capture_filters()

    def _analyze_response_content(self, headers: Dict[str, Any], content: Optional[bytes]) -> Dict[str, Any]:
        """根据当前 capture 配置分析响应内容与类型，返回结构化结果。"""
        ct = (headers.get('content-type') or '').lower()
        te = (headers.get('transfer-encoding') or '').lower()
        cl = (headers.get('content-length') or '')
        enable_streaming = self.capture_config.get('enable_streaming', False)
        enable_large_files = self.capture_config.get('enable_large_files', False)
        large_file_threshold = self.capture_config.get('large_file_threshold', 1048576)
        # 头信息判定 + 内容启发式双判定，避免缺失 content-type 时把二进制当文本
        is_bin = any(t in ct for t in ['video/', 'audio/', 'image/', 'application/octet-stream'])
        if not is_bin and content:
            try:
                # 含 NUL 字节或较高非打印字符比例，视为二进制
                if b"\x00" in content[:1024]:
                    is_bin = True
                else:
                    sample = content[:2048]
                    non_printable = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
                    if non_printable / max(1, len(sample)) > 0.1:
                        is_bin = True
            except Exception:
                pass
        is_image = ct.startswith('image/')
        is_video = ct.startswith('video/')
        is_stream = enable_streaming and ('chunked' in te or ct.startswith('multipart/'))
        is_large = enable_large_files and cl and str(cl).isdigit() and int(cl) > large_file_threshold
        # 文本预览
        if (is_bin or is_stream or is_large) and content:
            if is_stream:
                preview = f"[STREAMING] Size: {len(content)} bytes, Type: {ct}, Transfer-Encoding: {te}"
            elif is_bin:
                preview = f"[BINARY] Size: {len(content)} bytes, Type: {ct}"
            else:
                preview = f"[LARGE_FILE] Size: {len(content)} bytes, Type: {ct}"
        elif content:
            try:
                preview = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                preview = f"[ENCODED] Size: {len(content)} bytes"
        else:
            preview = ''
        return {
            'content_type': ct,
            'transfer_encoding': te,
            'content_length': cl,
            'is_binary': is_bin,
            'is_image': is_image,
            'is_video': is_video,
            'is_streaming': is_stream,
            'is_large_file': is_large,
            'preview': preview,
        }

    def set_internal_targets(self, targets: set):
        """设置内部不拦截的目标集合，元素为 (host, port)。"""
        self.internal_targets = targets or set()

    def set_internal_ports(self, ports: set):
        """设置内部不拦截的端口集合（仅按端口判断）。"""
        self.internal_web_ports = ports or set()

    def _load_capture_config(self) -> Dict[str, Any]:
        """加载抓包配置"""
        try:
            import yaml
            config_path = Path(self.config_path)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                return config.get('capture', {})
        except Exception as e:
            logger.warning(f"加载抓包配置失败: {e}")

        # 默认配置
        return {
            'enable_streaming': False,
            'enable_large_files': False,
            'large_file_threshold': 1048576,  # 1MB
            'save_binary_content': False,
            'binary_preview_max_bytes': 5242880  # 5MB 预览上限（仅用于预览，不做持久化）
        }

    def _compile_capture_filters(self) -> None:
        cfg = self.capture_config or {}
        inc = (cfg.get('include') or {})
        exc = (cfg.get('exclude') or {})

        def _to_list(v):
            if v is None:
                return []
            if isinstance(v, list):
                return v
            return [v]

        import re as _re
        self._inc_hosts = []
        for pat in _to_list(inc.get('hosts')):
            try:
                self._inc_hosts.append(_re.compile(str(pat), _re.IGNORECASE))
            except Exception:
                pass
        self._inc_paths = []
        for pat in _to_list(inc.get('paths')):
            try:
                self._inc_paths.append(_re.compile(str(pat)))
            except Exception:
                pass
        self._inc_methods = set([str(m).upper() for m in _to_list(inc.get('methods'))])
        self._exc_hosts = []
        for pat in _to_list(exc.get('hosts')):
            try:
                self._exc_hosts.append(_re.compile(str(pat), _re.IGNORECASE))
            except Exception:
                pass
        self._exc_paths = []
        for pat in _to_list(exc.get('paths')):
            try:
                self._exc_paths.append(_re.compile(str(pat)))
            except Exception:
                pass
        self._exc_methods = set([str(m).upper() for m in _to_list(exc.get('methods'))])

    def _should_capture(self, req: http.Request) -> bool:
        """判断是否应该捕获请求"""
        try:
            host = getattr(req, 'pretty_host', '') or ''
            path = getattr(req, 'path', '') or ''
            method = (getattr(req, 'method', '') or '').upper()

            # 检查排除条件（优先级最高）
            if self._is_excluded(host, path, method):
                return False

            # 如果没有包含条件，默认捕获所有
            if not self._has_include_conditions():
                return True

            # 检查包含条件
            return self._is_included(host, path, method)

        except Exception:
            return True

    def _is_excluded(self, host: str, path: str, method: str) -> bool:
        """检查是否被排除"""
        # 检查排除的方法
        if self._exc_methods and method in self._exc_methods:
            return True

        # 检查排除的主机
        if self._exc_hosts and self._matches_any_pattern(host, self._exc_hosts):
            return True

        # 检查排除的路径
        if self._exc_paths and self._matches_any_pattern(path, self._exc_paths):
            return True

        return False

    def _is_included(self, host: str, path: str, method: str) -> bool:
        """检查是否被包含"""
        # 检查包含的方法
        if self._inc_methods and method in self._inc_methods:
            return True

        # 检查包含的主机
        if self._inc_hosts and self._matches_any_pattern(host, self._inc_hosts):
            return True

        # 检查包含的路径
        if self._inc_paths and self._matches_any_pattern(path, self._inc_paths):
            return True

        return False

    def _has_include_conditions(self) -> bool:
        """检查是否有包含条件"""
        return bool(self._inc_methods or self._inc_hosts or self._inc_paths)

    def _matches_any_pattern(self, text: str, patterns: list) -> bool:
        """检查文本是否匹配任一模式"""
        for pattern in patterns:
            try:
                if pattern.search(text):
                    return True
            except Exception:
                continue
        return False

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        # 跳过对内部 Web 端口的拦截（包括二维码链接）
        try:
            if flow.request.port in self.internal_web_ports:
                return
            if (flow.request.pretty_host, flow.request.port) in self.internal_targets:
                return
        except Exception:
            pass
        start_time = time.time()

        # 先判定是否需要捕获；命中 exclude 则完全跳过规则与记录，仅透传
        try:
            capture_this = self._should_capture(flow.request)
            flow.metadata["uproxier_capture"] = bool(capture_this)
        except Exception:
            capture_this = True
            flow.metadata["uproxier_capture"] = True
        if not capture_this:
            return

        self.request_count += 1

        # 记录请求信息（原始）
        content_type = flow.request.headers.get('content-type', '').lower()
        transfer_encoding = flow.request.headers.get('transfer-encoding', '').lower()
        content_length = flow.request.headers.get('content-length', '')

        # 根据配置判断是否启用流媒体抓包
        enable_streaming = self.capture_config.get('enable_streaming', False)
        enable_large_files = self.capture_config.get('enable_large_files', False)
        large_file_threshold = self.capture_config.get('large_file_threshold', 1048576)

        # 判断是否为流媒体或大文件
        is_binary = any(t in content_type for t in ['video/', 'audio/', 'image/', 'application/octet-stream'])
        is_streaming = enable_streaming and ('chunked' in transfer_encoding or content_type.startswith('multipart/'))
        # Content-Length 可能为非数字（如缺失或被代理端异常设置），需安全判断
        is_large_file = enable_large_files and content_length and str(content_length).isdigit() and int(
            content_length) > large_file_threshold

        # 处理内容（根据配置决定是否处理流媒体和大文件）
        if (is_binary or is_streaming or is_large_file) and flow.request.content:
            if is_streaming:
                content_info = f"[STREAMING] Size: {len(flow.request.content)} bytes, Type: {content_type}, Transfer-Encoding: {transfer_encoding}"
            elif is_binary:
                content_info = f"[BINARY] Size: {len(flow.request.content)} bytes, Type: {content_type}"
            else:
                content_info = f"[LARGE_FILE] Size: {len(flow.request.content)} bytes, Type: {content_type}"
        elif flow.request.content:
            try:
                content_info = flow.request.content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content_info = f"[ENCODED] Size: {len(flow.request.content)} bytes"
        else:
            content_info = ''

        request_info = {
            'id': self.request_count,
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'host': flow.request.pretty_host,
            'port': flow.request.port,
            'path': flow.request.path,
            'scheme': flow.request.scheme,
            'headers': dict(flow.request.headers),
            'content': content_info,
            'content_size': len(flow.request.content) if flow.request.content else 0,
            'is_binary': is_binary,
            'is_streaming': is_streaming,
            'is_large_file': is_large_file,
            'transfer_encoding': transfer_encoding,
            'content_length': content_length,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status': 'pending'
        }

        modified_request = self.rules_engine.apply_request_rules(flow.request)
        if modified_request:
            flow.request = modified_request
            request_info['modified'] = True
            # 若请求阶段配置了短路直返响应，则直接返回
            try:
                sc_resp = getattr(flow.request, 'short_circuit_response', None)
                if sc_resp is not None:
                    flow.response = sc_resp
                    if flow.response.headers is not None:
                        flow.response.headers['X-Short-Circuit'] = 'true'
                    request_info.update({
                        'status': 'completed',
                        'response_status': flow.response.status_code,
                        'response_headers': dict(flow.response.headers),
                        'response_content': flow.response.get_text(strict=False) if hasattr(flow.response,
                                                                                            'get_text') else (
                            flow.response.text if hasattr(flow.response, 'text') else ''),
                        'response_content_size': len(flow.response.content) if getattr(flow.response, 'content',
                                                                                       None) else 0,
                        'response_time': 0,
                        'response_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    # 关键：短路分支也要归档（若命中捕获条件）
                    if self._should_capture(flow.request):
                        self.traffic_data.append(request_info)
                        self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)
                    return
            except Exception:
                pass
            # 计算修改后的预览
            mod_ct = flow.request.headers.get('content-type', '').lower()
            mod_te = flow.request.headers.get('transfer-encoding', '').lower()
            mod_cl = flow.request.headers.get('content-length', '')
            mod_is_binary = any(t in mod_ct for t in ['video/', 'audio/', 'image/', 'application/octet-stream'])
            mod_is_streaming = self.capture_config.get('enable_streaming', False) and (
                    'chunked' in mod_te or mod_ct.startswith('multipart/'))
            mod_is_large_file = self.capture_config.get('enable_large_files', False) and mod_cl and int(
                mod_cl) > self.capture_config.get('large_file_threshold', 1048576)
            if (mod_is_binary or mod_is_streaming or mod_is_large_file) and flow.request.content:
                if mod_is_streaming:
                    mod_content_info = f"[STREAMING] Size: {len(flow.request.content)} bytes, Type: {mod_ct}, Transfer-Encoding: {mod_te}"
                elif mod_is_binary:
                    mod_content_info = f"[BINARY] Size: {len(flow.request.content)} bytes, Type: {mod_ct}"
                else:
                    mod_content_info = f"[LARGE_FILE] Size: {len(flow.request.content)} bytes, Type: {mod_ct}"
            elif flow.request.content:
                try:
                    mod_content_info = flow.request.content.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    mod_content_info = f"[ENCODED] Size: {len(flow.request.content)} bytes"
            else:
                mod_content_info = ''
            request_info['modified_headers'] = dict(flow.request.headers)
            request_info['modified_content'] = mod_content_info
            request_info['modified_content_size'] = len(flow.request.content) if flow.request.content else 0

        if capture_this:
            self.traffic_data.append(request_info)
            self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)

        # 添加处理时间
        flow.request.timestamp_start = start_time

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """在存在请求短路规则时接受 HTTPS CONNECT，避免上游 502，确保内层请求进入 request()."""
        try:
            host = flow.request.pretty_host
            should_accept = False
            for r in getattr(self.rules_engine, 'rules', []):
                if not getattr(r, 'enabled', True):
                    continue
                # 必须含请求短路动作
                if not any(isinstance(step, dict) and step.get('action') == 'short_circuit' for step in
                           getattr(r, 'request_pipeline', [])):
                    continue
                try:
                    if r._host_re is None or r._host_re.search(host):
                        should_accept = True
                        break
                except Exception:
                    continue
            if should_accept:
                flow.response = http.Response.make(200, b"", {})
        except Exception:
            pass

    def response(self, flow: http.HTTPFlow) -> None:
        """处理响应"""
        # 跳过对内部 Web 端口的处理
        try:
            if flow.request.port in self.internal_web_ports:
                return
            if (flow.request.pretty_host, flow.request.port) in self.internal_targets:
                return
        except Exception:
            pass
        # 非捕获请求：不采集响应、不应用规则，直接返回
        try:
            if not bool(flow.metadata.get("uproxier_capture", True)):
                return
        except Exception:
            pass
        end_time = time.time()

        request_info = None
        for req in self.traffic_data:
            if req['url'] == flow.request.pretty_url and req['status'] == 'pending':
                request_info = req
                break

        if request_info:
            # 在应用响应规则前，先快照原始响应（用于对比展示）
            orig_resp_headers = dict(flow.response.headers)
            _orig = self._analyze_response_content(orig_resp_headers, flow.response.content)
            orig_resp_content_info = _orig['preview']

            try:
                setattr(flow.response, 'request', flow.request)
            except Exception:
                pass
            modified_response = self.rules_engine.apply_response_rules(flow.response)
            if modified_response:
                flow.response = modified_response
                request_info['response_modified'] = True
                request_info['response_original_headers'] = orig_resp_headers
                request_info['response_original_content'] = orig_resp_content_info

            # 更新响应信息（以规则处理后的响应为准）
            _final = self._analyze_response_content(flow.response.headers, flow.response.content)
            response_content_type = _final['content_type']
            response_transfer_encoding = _final['transfer_encoding']
            response_content_length = _final['content_length']
            is_response_binary = _final['is_binary']
            is_response_streaming = _final['is_streaming']
            is_response_large_file = _final['is_large_file']
            response_content_info = _final['preview']

            # 非阻塞延迟：在独立线程/计时器中完成等待，避免阻塞当前处理
            delay_time = flow.response.headers.get('X-Delay-Time')
            jitter = flow.response.headers.get('X-Delay-Jitter')
            distrib = flow.response.headers.get('X-Delay-Distrib')
            p50 = flow.response.headers.get('X-Delay-P50')
            p95 = flow.response.headers.get('X-Delay-P95')
            p99 = flow.response.headers.get('X-Delay-P99')

            def _compute_delay_ms():
                try:
                    import random
                    base_ms = int(delay_time) if delay_time else 0
                    jit_ms = int(jitter) if jitter else 0
                    total_ms = base_ms
                    if distrib:
                        d = str(distrib).lower()
                        if d == 'uniform':
                            total_ms += random.randint(0, jit_ms)
                        elif d == 'normal':
                            total_ms = int(max(0, random.normalvariate(base_ms, max(1, jit_ms / 2))))
                        elif d == 'exponential':
                            lam = 1.0 / max(1, base_ms if base_ms > 0 else 1)
                            total_ms = int(random.expovariate(lam))
                    elif jit_ms:
                        total_ms += random.randint(0, jit_ms)
                    buckets = []
                    if p50:
                        buckets.append((0.5, int(p50)))
                    if p95:
                        buckets.append((0.45, int(p95)))
                    if p99:
                        buckets.append((0.04, int(p99)))
                    if buckets:
                        r = random.random()
                        acc = 0.0
                        for prob, val in buckets:
                            acc += prob
                            if r <= acc:
                                total_ms = val
                                break
                    return max(0, int(total_ms))
                except Exception:
                    return 0

            total_ms = _compute_delay_ms()
            if total_ms > 0:
                # 强制持有并延后发送，确保客户端实际延迟
                try:
                    if hasattr(flow, 'reply') and flow.reply is not None and hasattr(flow.reply, 'take') and hasattr(
                            flow.reply, 'send'):
                        flow.reply.take()
                        try:
                            flow.response.headers['X-Delay-Applied'] = 'true'
                            flow.response.headers['X-Delay-Effective'] = str(int(total_ms))
                        except Exception:
                            pass
                        if not self.silent:
                            try:
                                logger.info(f"响应延迟 {total_ms}ms → {flow.request.method} {flow.request.pretty_url}")
                            except Exception:
                                pass
                        time.sleep(total_ms / 1000.0)
                        flow.reply.send()
                        try:
                            request_info['response_time'] = (request_info.get('response_time') or 0) + (
                                    total_ms / 1000.0)
                        except Exception:
                            pass
                    else:
                        try:
                            flow.response.headers['X-Delay-Applied'] = 'true'
                            flow.response.headers['X-Delay-Effective'] = str(int(total_ms))
                        except Exception:
                            pass
                        if not self.silent:
                            try:
                                logger.info(f"响应延迟(降级) {total_ms}ms → {flow.request.method} {flow.request.pretty_url}")
                            except Exception:
                                pass
                        time.sleep(total_ms / 1000.0)
                        try:
                            request_info['response_time'] = (request_info.get('response_time') or 0) + (
                                    total_ms / 1000.0)
                        except Exception:
                            pass
                except Exception:
                    pass

            # 计算最终响应信息（在延迟完成后再写入，以保持前后端一致）
            _final2 = self._analyze_response_content(flow.response.headers, flow.response.content)
            response_content_type = _final2['content_type']
            response_transfer_encoding = _final2['transfer_encoding']
            response_content_length = _final2['content_length']
            is_response_binary = _final2['is_binary']
            is_response_image = _final2.get('is_image', False)
            is_response_video = _final2.get('is_video', False)
            is_response_streaming = _final2['is_streaming']
            is_response_large_file = _final2['is_large_file']
            response_content_info = _final2['preview']

            # 最终更新（此时如果设置了延迟，已经延后完成）
            request_info.update({
                'status': 'completed',
                'response_status': flow.response.status_code,
                'response_headers': dict(flow.response.headers),
                'response_content': response_content_info,
                'response_content_size': len(flow.response.content) if flow.response.content else 0,
                'is_response_binary': is_response_binary,
                'is_response_image': is_response_image,
                'is_response_video': is_response_video,
                'is_response_streaming': is_response_streaming,
                'is_response_large_file': is_response_large_file,
                'response_transfer_encoding': response_transfer_encoding,
                'response_content_length': response_content_length,
                'response_time': (end_time - flow.request.timestamp_start) + (
                    total_ms / 1000.0 if 'total_ms' in locals() and total_ms else 0),
                'response_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            # 为图片/视频生成预览（限制大小；与 save_binary_content 解耦，默认只按阈值与类型）。
            try:
                if (is_response_image or is_response_video) and flow.response.content:
                    max_bytes = int(self.capture_config.get('binary_preview_max_bytes', 5242880))
                    if len(flow.response.content) <= max_bytes:
                        # 直接注册到 Web 内存缓存，返回 URL
                        try:
                            url = self.web_interface.register_binary_preview(
                                request_info.get('id'), flow.response.content,
                                response_content_type or 'application/octet-stream'
                            )
                            if url:
                                request_info['response_preview_url'] = url
                                request_info[
                                    'response_preview_mime'] = response_content_type or 'application/octet-stream'
                        except Exception:
                            pass
            except Exception:
                pass

            # 更新 Web 界面数据（仅在最终状态写入）
            self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)

            self._maybe_persist(request_info)

    def error(self, flow: http.HTTPFlow) -> None:
        """处理错误"""
        if not self.silent:
            logger.error(f"代理错误: {flow.error}")

        # 更新请求状态为错误
        for req in self.traffic_data:
            if req['url'] == flow.request.pretty_url and req['status'] == 'pending':
                req.update({
                    'status': 'error',
                    'error': str(flow.error),
                    'error_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                break

        self._maybe_persist(
            next((r for r in self.traffic_data if r['url'] == flow.request.pretty_url and r['status'] == 'error'),
                 None))

    def _maybe_persist(self, record: Optional[Dict[str, Any]]):
        if not record or not self.save_path:
            return
        try:
            if self.save_format == 'jsonl':
                with open(self.save_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(record, ensure_ascii=False) + '\n')
        except Exception as e:
            if not self.silent:
                logger.error(f"保存请求数据失败: {e}")


class ProxyServer:
    """代理服务器主类"""

    def __init__(self, config_path: str = "config.yaml", save_path: Optional[str] = None, save_format: str = 'jsonl',
                 silent: bool = False, enable_https: Optional[bool] = None):
        self.config_path = config_path
        self.save_path = save_path
        self.save_format = save_format
        self.silent = silent
        self.enable_https_override = enable_https
        self.rules_engine = RulesEngine(config_path, silent=self.silent)
        self.cert_manager = CertificateManager(silent=self.silent)
        self.web_interface = WebInterface()
        self.addon = ProxyAddon(self.rules_engine, self.web_interface, save_path=save_path, save_format=save_format,
                                silent=self.silent, config_path=self.config_path)
        self.master = None
        self.is_running = False
        self._process = None  # 用于存储异步启动的进程对象

    def start(self, host: str = "127.0.0.1", port: int = 8001, web_port: int = 8002):
        """启动代理服务器"""
        try:
            # 读取配置：是否启用 HTTPS 拦截
            enable_https = True
            try:
                import yaml
                config_path = Path(self.config_path)
                if config_path.exists():
                    with open(config_path, 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f) or {}
                    enable_https = bool(((cfg or {}).get('proxy') or {}).get('enable_https', True))
            except Exception as _:
                enable_https = True

            # CLI 覆盖配置优先
            if self.enable_https_override is not None:
                enable_https = bool(self.enable_https_override)

            # 仅在启用 HTTPS 时才准备证书
            if enable_https:
                self.cert_manager.ensure_certificates()

            # 在静默模式下抑制 mitmproxy 的日志输出
            if self.silent:
                import logging
                import os
                import sys

                # 抑制 mitmproxy 的所有日志
                logging.getLogger('mitmproxy').setLevel(logging.ERROR)
                logging.getLogger('mitmproxy.proxy').setLevel(logging.ERROR)
                logging.getLogger('mitmproxy.proxy.mode_servers').setLevel(logging.ERROR)
                logging.getLogger('mitmproxy.proxy.server').setLevel(logging.ERROR)
                logging.getLogger('mitmproxy.proxy.protocol').setLevel(logging.ERROR)
                logging.getLogger('mitmproxy.proxy.layers').setLevel(logging.ERROR)
                # 抑制 urllib3 的日志
                logging.getLogger('urllib3').setLevel(logging.ERROR)
                # 抑制 asyncio 的日志
                logging.getLogger('asyncio').setLevel(logging.ERROR)

                # 设置环境变量抑制 mitmproxy 输出
                os.environ['MITMPROXY_QUIET'] = '1'
                os.environ['MITMPROXY_TERMLOG_VERBOSITY'] = 'error'

            # 配置 mitmproxy
            if enable_https:
                opts = options.Options(
                    listen_host=host,
                    listen_port=port,
                    confdir=str(self.cert_manager.cert_dir),
                    ssl_insecure=True,
                    http2=False
                )
            else:
                # 不拦截 TLS：通过 ignore_hosts 将 TLS 连接直通（不解密）
                # 依然可以代理 HTTP 请求
                opts = options.Options(
                    listen_host=host,
                    listen_port=port,
                    ssl_insecure=False,
                    http2=False,
                    ignore_hosts=[r".*"]
                )

            # 启动 Web 界面：若代理绑定在回环(127.0.0.1/localhost)，则让 Web 绑定 0.0.0.0，确保局域网可访问
            if host in ("127.0.0.1", "localhost", "::1"):
                web_host = "0.0.0.0"
            else:
                web_host = host if host not in ("0.0.0.0", "::") else "0.0.0.0"
            # 注入运行时元信息供 /api/meta 使用
            try:
                # 计算用于展示的 web 主机（0.0.0.0 时转为局域网 IP）
                web_display_host = self._prefer_lan_host(web_host)
                # 读取证书路径与指纹
                cert_path = None
                cert_fingerprint = None
                try:
                    info = self.cert_manager.get_certificate_info()
                    if 'error' not in info:
                        cert_path = info.get('cert_path')
                        import subprocess as _sp
                        if cert_path:
                            fres = _sp.run(
                                ["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"],
                                check=True, capture_output=True, text=True)
                            for line in fres.stdout.splitlines():
                                if "Fingerprint=" in line:
                                    cert_fingerprint = line.split("=", 1)[1].strip().replace(":", "")
                                    break
                except Exception:
                    pass
                self.web_interface.server_meta = {
                    'config_path': str(Path(self.config_path).resolve()),
                    'proxy': {'host': host, 'port': port},
                    'web': {'host': web_host, 'port': web_port, 'display_host': web_display_host},
                    'https_enabled': bool(enable_https),
                    'certificate': {'path': cert_path, 'sha256': cert_fingerprint}
                }
            except Exception:
                self.web_interface.server_meta = {}
            self.web_interface.start(web_port, host=web_host, silent=self.silent)

            # 启动代理服务器（展示友好地址）
            display_host = self._prefer_lan_host(host)
            if not self.silent:
                logger.info(f"启动代理服务器: {display_host}:{port}")
                logger.info(f"Web 界面: http://{display_host}:{web_port}")
                logger.info(f"HTTPS 拦截: {'启用' if enable_https else '禁用（TLS 直通）'}")
                logger.info("按 Ctrl+C 停止服务器")

            self.is_running = True

            # 在事件循环中初始化并运行 DumpMaster
            async def _run_master():
                self.master = DumpMaster(opts)
                self.master.addons.add(self.addon)
                try:
                    import logging as _logging
                    for ln in (
                            "mitmproxy.proxy.server",
                            "mitmproxy.proxy.layers.tls",
                            "mitmproxy.proxy.tls",
                            "mitmproxy.tls",
                    ):
                        lg = _logging.getLogger(ln)
                        lg.setLevel(_logging.ERROR)
                        lg.propagate = False
                except Exception:
                    pass

                # 将 Web 界面目标标记为内部域，避免规则误拦
                try:
                    # 端口级跳过：即使 host 是 127.0.0.1/本机 IP/0.0.0.0 变化，也不拦 Web 端口
                    self.addon.set_internal_ports({web_port})
                    internal_host = web_host
                    self.addon.set_internal_targets({(internal_host, web_port)})
                except Exception:
                    pass

                # 在静默模式下重定向所有输出
                if self.silent:
                    import os
                    import sys
                    from contextlib import redirect_stdout, redirect_stderr

                    # 临时重定向 stdout 和 stderr 到 /dev/null
                    with open(os.devnull, 'w') as devnull:
                        with redirect_stdout(devnull), redirect_stderr(devnull):
                            await self.master.run()
                else:
                    await self.master.run()

            asyncio.run(_run_master())

        except KeyboardInterrupt:
            if not self.silent:
                logger.info("正在停止代理服务器...")
        except Exception as e:
            if not self.silent:
                logger.error(f"启动代理服务器失败: {e}")
        finally:
            self.stop()

    def start_async(self, host: str = "127.0.0.1", port: int = 8001, web_port: int = 8002):
        """异步启动代理服务器（非阻塞）"""
        import subprocess
        import sys
        import os

        # 构建启动命令
        cmd = [sys.executable, "cli.py", "start",
               "--host", host, "--port", str(port),
               "--web-port", str(web_port), "--config", self.config_path, "--silent"]

        if self.save_path:
            cmd.extend(["--save", self.save_path, "--save-format", self.save_format])

        if self.enable_https_override is not None:
            if self.enable_https_override:
                cmd.append("--enable-https")
            else:
                cmd.append("--disable-https")

        try:
            # 启动后台进程
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                cwd=os.getcwd()
            )

            # 等待进程启动
            time.sleep(0.5)

            # 检查进程是否还在运行
            if process.poll() is not None:
                # 进程已退出，获取错误信息
                stdout, stderr = process.communicate()
                error_msg = stderr.decode() if stderr else "无错误信息"
                stdout_msg = stdout.decode() if stdout else "无输出信息"
                raise RuntimeError(f"后台进程启动失败: {error_msg}\n输出: {stdout_msg}")

            # 设置运行状态
            self.is_running = True
            self._process = process  # 保存进程引用，用于停止

            if not self.silent:
                logger.info(f"服务器已在后台启动 (PID: {process.pid})")
                logger.info(f"代理地址: {host}:{port}")
                logger.info(f"Web 界面: http://{host}:{web_port}")

            return process

        except Exception as e:
            if not self.silent:
                logger.error(f"启动失败: {e}")
            raise

    def stop(self):
        """停止代理服务器"""
        if hasattr(self, '_process') and self._process:
            # 停止通过 start_async 启动的进程
            import subprocess
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
            except Exception as e:
                if not self.silent:
                    logger.error(f"停止进程失败: {e}")
            finally:
                self._process = None

        if self.master:
            self.master.shutdown()
        if self.web_interface:
            self.web_interface.stop()
        self.is_running = False
        if not self.silent:
            logger.info("代理服务器已停止")

    def _prefer_lan_host(self, bind_host: str) -> str:
        """当绑定 0.0.0.0/:: 时优先返回局域网 IP，否则返回原 host。失败回退 127.0.0.1。"""
        try:
            if bind_host in ("0.0.0.0", "::"):
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                lan = s.getsockname()[0]
                s.close()
                return lan or "127.0.0.1"
            return bind_host
        except Exception:
            return "127.0.0.1"

    def get_stats(self) -> Dict[str, Any]:
        """获取代理服务器统计信息"""
        return {
            'is_running': self.is_running,
            'request_count': self.addon.request_count,
            'traffic_count': len(self.addon.traffic_data),
            'rules_count': len(self.rules_engine.rules)
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="代理服务器")
    parser.add_argument("--host", default="0.0.0.0", help="代理服务器监听地址")
    parser.add_argument("--port", type=int, default=8080, help="代理服务器端口")
    parser.add_argument("--web-port", type=int, default=8081, help="Web 界面端口")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    parser.add_argument("--log-level", default="INFO", help="日志级别")

    args = parser.parse_args()

    # 配置日志
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 启动代理服务器
    proxy = ProxyServer(args.config)
    proxy.start(args.host, args.port, args.web_port)
