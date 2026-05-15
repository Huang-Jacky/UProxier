#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import logging
import os
import pathlib
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List

from mitmproxy import http
from mitmproxy import options
from mitmproxy import tls as mitm_tls
from mitmproxy.tools.dump import DumpMaster

from uproxier.certificate_manager import CertificateManager
from uproxier.exceptions import ProxyStartupError
from uproxier.rules_engine import RulesEngine, default_config_path
from uproxier.web_interface import WebInterface
from uproxier.utils.http import get_header_value
from uproxier.utils.network import get_display_host
from uproxier.utils.traffic import record_for_json_output

logger = logging.getLogger(__name__)

# 默认监听地址
DEFAULT_HOST = "0.0.0.0"


def _local_port_accepting_connections(port: int, timeout: float = 0.5) -> bool:
    """本机 ``127.0.0.1:port`` 是否已有服务 accept（与 ``cli.is_service_ready`` 同类检测）。"""
    try:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex(("127.0.0.1", port)) == 0
        finally:
            sock.close()
    except Exception:
        return False


class ProxyAddon:
    """代理服务器插件，处理请求和响应"""

    def __init__(self, rules_engine: RulesEngine, web_interface: WebInterface, save_path: Optional[str] = None,
                 silent: bool = False, config_path: Optional[str] = None):
        self.rules_engine = rules_engine
        self.web_interface = web_interface
        self.silent = silent
        self.request_count = 0
        # 与 traffic_data 共用一把可重入锁：避免并发 append / 遍历查找时偶发错配或漏匹配
        self._traffic_state_lock = threading.RLock()
        self.traffic_data = []
        self.save_path = None
        self.internal_targets = set()
        self.internal_web_ports = set()
        self.config_path = config_path or default_config_path()
        if save_path:
            p = pathlib.Path(save_path)
            if p.is_dir():
                p = p / 'traffic.jsonl'
            p.parent.mkdir(parents=True, exist_ok=True)
            self.save_path = str(p)
            # 每次启动时清空文件，确保覆盖而不是追加
            if p.exists():
                p.unlink()

        # 读取抓包配置
        self.capture_config = self._load_capture_config()
        # 预编译 include/exclude 过滤器
        self._compile_capture_filters()

    def _analyze_response_content(self, headers: Dict[str, Any], content: Optional[bytes]) -> Dict[str, Any]:
        """根据当前 capture 配置分析响应内容与类型，返回结构化结果。"""
        ct = (get_header_value(headers, 'content-type') or '').lower()
        te = (get_header_value(headers, 'transfer-encoding') or '').lower()
        cl = get_header_value(headers, 'content-length') or ''
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

    def set_internal_targets(self, targets: set) -> None:
        """设置内部不拦截的目标集合，元素为 (host, port)。"""
        self.internal_targets = targets or set()

    def set_internal_ports(self, ports: set) -> None:
        """设置内部不拦截的端口集合（仅按端口判断）。"""
        self.internal_web_ports = ports or set()

    def _load_capture_config(self) -> Dict[str, Any]:
        """加载抓包配置，支持继承"""
        try:
            import yaml
            config_path = Path(self.config_path)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)

                # 处理配置文件继承
                if 'extends' in config:
                    config = self._resolve_extends_for_capture(config, config_path.parent)

                return config.get('capture', {})
        except Exception as e:
            logger.warning(f"加载抓包配置失败: {e}")

        # 默认配置
        return {
            'enable_streaming': False,
            'enable_large_files': False,
            'large_file_threshold': 1048576,  # 1MB
            'save_binary_content': False,
            'binary_preview_max_bytes': 5242880,  # 5MB 预览上限（仅用于预览，不做持久化）
            # 为 true 且使用 --save 时，在仍为 pending 时再追加一行 JSONL（会与 completed 形成两行，校验场景请保持 false）
            'jsonl_write_pending': False,
        }

    def _resolve_extends_for_capture(self, config: Dict, current_dir: Path) -> Dict:
        """解析配置文件继承（仅用于 capture 配置）"""
        if 'extends' not in config:
            return config

        extends_file = config['extends']

        if not Path(extends_file).is_absolute():
            extends_file = current_dir / extends_file

        extends_file = Path(extends_file).resolve()

        if not extends_file.exists():
            return config

        try:
            import yaml
            with open(extends_file, 'r', encoding='utf-8') as f:
                base_config = yaml.safe_load(f)

            # 递归解析基础配置的继承
            base_config = self._resolve_extends_for_capture(base_config, Path(extends_file).parent)

            # 合并 capture 配置
            merged_config = base_config.copy()
            if 'capture' in config:
                if 'capture' in merged_config:
                    merged_config['capture'].update(config['capture'])
                else:
                    merged_config['capture'] = config['capture']

            return merged_config
        except Exception:
            return config

    @staticmethod
    def _host_pattern_to_regex(pat: str) -> str:
        """将 host 配置转为正则：若含 \\、^、$ 则视为正则；否则按通配符 * ? 转为正则。"""
        import re as _re
        s = str(pat).strip()
        if "\\" in s or (s.startswith("^") or s.endswith("$")):
            return s
        out = []
        for c in s:
            if c == "*":
                out.append(".*")
            elif c == "?":
                out.append(".")
            elif c == ".":
                out.append(r"\.")
            else:
                out.append(c)
        return "^" + "".join(out) + "$"

    def _compile_capture_filters(self) -> None:
        cfg = self.capture_config or {}
        inc = (cfg.get('include') or {})
        exc = (cfg.get('exclude') or {})

        def _to_list(v: Any) -> List[str]:
            if v is None:
                return []
            if isinstance(v, list):
                return v
            return [v]

        import re as _re
        self._inc_hosts = []
        for pat in _to_list(inc.get('hosts')):
            try:
                regex = self._host_pattern_to_regex(pat)
                self._inc_hosts.append(_re.compile(regex, _re.IGNORECASE))
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
                regex = self._host_pattern_to_regex(pat)
                self._exc_hosts.append(_re.compile(regex, _re.IGNORECASE))
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

    @staticmethod
    def _same_traffic_id(stored: Any, meta: Any) -> bool:
        """判断 traffic 记录 id 与 flow.metadata 中的请求 id 是否同一（兼容 int/str）。"""
        if meta is None or stored is None:
            return False
        try:
            return int(stored) == int(meta)
        except (TypeError, ValueError):
            return str(stored) == str(meta)

    @staticmethod
    def _flow_id_str(flow: http.HTTPFlow) -> str:
        """mitmproxy 每条 flow 的稳定 id，用于 request/response 精确关联（优于同 URL 多 pending）。"""
        try:
            fid = getattr(flow, "id", None)
            if fid is not None and str(fid).strip():
                return str(fid).strip()
        except Exception:
            pass
        return str(id(flow))

    def _jsonl_pending_enabled(self) -> bool:
        if not self.save_path:
            return False
        return bool(self.capture_config.get("jsonl_write_pending", False))

    def _emit_pending_jsonl_once(self, request_info: Dict[str, Any]) -> None:
        """每条请求最多写一行 pending 快照（避免短路等路径重复写）。"""
        if not self._jsonl_pending_enabled() or request_info.get("_jsonl_pending_line_written"):
            return
        request_info["_jsonl_pending_line_written"] = True
        self._maybe_persist(request_info, jsonl_phase="pending")

    def _find_traffic_row_for_flow(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """按 flow_id → request_id →「唯一 URL pending」顺序解析 traffic 行。"""
        flow_id = None
        req_id = None
        try:
            flow_id = flow.metadata.get("uproxier_flow_id")
        except Exception:
            flow_id = None
        try:
            req_id = flow.metadata.get("uproxier_request_id")
        except Exception:
            req_id = None
        pretty_url = getattr(flow.request, "pretty_url", "") or ""
        with self._traffic_state_lock:
            if flow_id is not None:
                s = str(flow_id)
                for req in self.traffic_data:
                    if str(req.get("flow_id") or "") == s:
                        return req
            if req_id is not None:
                for req in self.traffic_data:
                    if self._same_traffic_id(req.get("id"), req_id):
                        return req
            cands = [r for r in self.traffic_data if self._pending_row_matches_request_url(r, pretty_url)]
            if len(cands) == 1:
                return cands[0]
            if len(cands) > 1:
                logger.warning(
                    "多个 pending 同 URL，跳过 URL 回退以免错绑: n=%s url=%s",
                    len(cands),
                    pretty_url[:160],
                )
        return None

    def _persist_response_orphan(self, flow: http.HTTPFlow, pretty_url: str, req_id: Any, flow_id: Any) -> None:
        """response 无法关联到 traffic 行时仍写一条 JSONL 便于对账（修复点 3）。"""
        if not self.save_path:
            return
        row: Dict[str, Any] = {
            "jsonl_phase": "orphan_response",
            "method": getattr(flow.request, "method", "?"),
            "url": pretty_url,
            "metadata_req_id": req_id,
            "flow_id": flow_id,
            "persist_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            if getattr(flow, "response", None) is not None:
                row["response_status"] = flow.response.status_code
        except Exception:
            pass
        self._maybe_persist(row)

    @staticmethod
    def _pending_row_matches_request_url(req: Dict[str, Any], pretty_url: str) -> bool:
        """pending 行与当前请求的 pretty_url 对齐（含规则改写后的 URL）。"""
        if req.get("status") != "pending":
            return False
        u = req.get("url")
        if u == pretty_url:
            return True
        mod = req.get("modified_url")
        return mod == pretty_url if mod else False

    @staticmethod
    def _parse_content_length_bytes(cl: Any) -> Optional[int]:
        """安全解析 Content-Length，非法或非数字时返回 None。"""
        if cl is None:
            return None
        s = str(cl).strip()
        if not s.isdigit():
            return None
        try:
            return int(s)
        except ValueError:
            return None

    def tls_clienthello(self, data: mitm_tls.ClientHelloData) -> None:
        """TLS ClientHello：若 SNI 命中 exclude.hosts 则不解密，直接透传（解决 ignore_hosts 不可靠的问题）"""
        try:
            sni = (data.client_hello.sni or "").strip()
            if not sni:
                return
            if self._exc_hosts and self._matches_any_pattern(sni, self._exc_hosts):
                data.ignore_connection = True
                if not self.silent:
                    logger.info("TLS 直通（exclude.hosts）: %s", sni)
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow) -> None:
        """处理请求"""
        # 跳过对内部 Web 端口的拦截（包括二维码链接）
        try:
            if flow.request.port in self.internal_web_ports:
                try:
                    flow.metadata["uproxier_capture"] = False
                    flow.metadata["uproxier_skip"] = "internal_web_port"
                except Exception:
                    pass
                return
            if (flow.request.pretty_host, flow.request.port) in self.internal_targets:
                try:
                    flow.metadata["uproxier_capture"] = False
                    flow.metadata["uproxier_skip"] = "internal_target"
                except Exception:
                    pass
                return
        except Exception:
            pass
        start_time = time.time()

        # 先判定是否需要捕获；命中 exclude 则不捕获、不执行规则，对应域名也不做 TLS 解密，直接透传
        try:
            capture_this = self._should_capture(flow.request)
            flow.metadata["uproxier_capture"] = bool(capture_this)
        except Exception:
            capture_this = True
            flow.metadata["uproxier_capture"] = True
        if not capture_this:
            logger.warning(
                "跳过捕获(未命中 capture.include 或命中 exclude): %s %s",
                getattr(flow.request, 'method', '?'),
                getattr(flow.request, 'pretty_url', '?'),
            )
            return

        flow_id_str = self._flow_id_str(flow)
        with self._traffic_state_lock:
            self.request_count += 1
            req_id_assigned = self.request_count
            try:
                flow.metadata["uproxier_request_id"] = req_id_assigned
                flow.metadata["uproxier_flow_id"] = flow_id_str
            except Exception:
                pass
            request_info: Dict[str, Any] = {
                'id': req_id_assigned,
                'flow_id': flow_id_str,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'host': flow.request.pretty_host,
                'port': flow.request.port,
                'path': flow.request.path,
                'scheme': flow.request.scheme,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'status': 'pending',
            }
            self.traffic_data.append(request_info)

        # 记录请求信息（原始），写入与 traffic_data 中占位行同一 dict
        content_type = (get_header_value(flow.request.headers, 'content-type') or '').lower()
        transfer_encoding = (get_header_value(flow.request.headers, 'transfer-encoding') or '').lower()
        content_length = get_header_value(flow.request.headers, 'content-length') or ''

        # 根据配置判断是否启用流媒体抓包
        enable_streaming = self.capture_config.get('enable_streaming', False)
        enable_large_files = self.capture_config.get('enable_large_files', False)
        large_file_threshold = self.capture_config.get('large_file_threshold', 1048576)

        # 判断是否为流媒体或大文件
        is_multipart = content_type.startswith('multipart/form-data')
        is_binary = any(t in content_type for t in ['video/', 'audio/', 'image/', 'application/octet-stream'])
        is_streaming = enable_streaming and ('chunked' in transfer_encoding or content_type.startswith('multipart/'))
        # Content-Length 可能为非数字（如缺失或被代理端异常设置），需安全判断
        is_large_file = enable_large_files and content_length and str(content_length).isdigit() and int(
            content_length) > large_file_threshold

        # 处理内容（根据配置决定是否处理流媒体和大文件）
        if (is_multipart or is_binary or is_streaming or is_large_file) and flow.request.content:
            if is_multipart:
                content_info = f"[MULTIPART] Size: {len(flow.request.content)} bytes, Type: {content_type}"
            elif is_streaming:
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

        request_info.update({
            'headers': dict(flow.request.headers),
            'content': content_info,
            'content_size': len(flow.request.content) if flow.request.content else 0,
            'is_multipart': is_multipart,
            'is_binary': is_binary,
            'is_streaming': is_streaming,
            'is_large_file': is_large_file,
            'transfer_encoding': transfer_encoding,
            'content_length': content_length,
        })

        try:
            modified_request, applied_rule_names = self.rules_engine.apply_request_rules(flow.request)
            if modified_request:
                flow.request = modified_request
                request_info['modified'] = True
                request_info['request_rules_applied'] = applied_rule_names
                request_info['modified_url'] = flow.request.pretty_url
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
                        # 短路在此已填好响应摘要；JSONL 只在 response() 写一行，避免与 response() 内
                        # _maybe_persist 重复（否则同一 id 两条、且首条缺 is_response_* 等字段）。
                        flow.request.timestamp_start = start_time
                        if capture_this:
                            self._emit_pending_jsonl_once(request_info)
                            self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)
                        return
                except Exception as e:
                    logger.exception("短路响应处理异常")
                    if capture_this:
                        self._emit_handler_failure_record(request_info, e, status='short_circuit_handler_error')
                    return
                # 计算修改后的预览
                mod_ct = (get_header_value(flow.request.headers, 'content-type') or '').lower()
                mod_te = (get_header_value(flow.request.headers, 'transfer-encoding') or '').lower()
                mod_cl = get_header_value(flow.request.headers, 'content-length') or ''
                mod_is_multipart = mod_ct.startswith('multipart/form-data')
                mod_is_binary = any(t in mod_ct for t in ['video/', 'audio/', 'image/', 'application/octet-stream'])
                mod_is_streaming = self.capture_config.get('enable_streaming', False) and (
                        'chunked' in mod_te or mod_ct.startswith('multipart/'))
                mod_cl_val = self._parse_content_length_bytes(mod_cl)
                mod_is_large_file = bool(
                    self.capture_config.get('enable_large_files', False)
                    and mod_cl_val is not None
                    and mod_cl_val > self.capture_config.get('large_file_threshold', 1048576)
                )
                if (mod_is_multipart or mod_is_binary or mod_is_streaming or mod_is_large_file) and flow.request.content:
                    if mod_is_multipart:
                        mod_content_info = f"[MULTIPART] Size: {len(flow.request.content)} bytes, Type: {mod_ct}"
                    elif mod_is_streaming:
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
                request_info['modified_is_multipart'] = mod_is_multipart

            if capture_this:
                self._emit_pending_jsonl_once(request_info)
                self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)

            # 添加处理时间
            flow.request.timestamp_start = start_time
        except Exception as e:
            logger.exception("UProxier request() 处理异常，已写入兜底记录")
            if capture_this:
                self._emit_handler_failure_record(request_info, e, status='request_handler_error')
            raise

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
        # 注意：metadata 缺省视为未捕获（勿用 default=True，否则易误判并产生「无法匹配」的孤儿 response）
        try:
            if not flow.metadata.get("uproxier_capture"):
                return
        except Exception:
            return
        end_time = time.time()

        req_id = None
        try:
            req_id = flow.metadata.get("uproxier_request_id")
        except Exception:
            req_id = None

        pretty_url = getattr(flow.request, "pretty_url", "") or ""

        request_info = self._find_traffic_row_for_flow(flow)

        if request_info is None:
            logger.warning(
                "response 未匹配到 traffic 记录（将无 completed 更新/落盘）: method=%s url=%s metadata_req_id=%s",
                getattr(flow.request, "method", "?"),
                pretty_url,
                req_id,
            )
            try:
                fid = flow.metadata.get("uproxier_flow_id")
            except Exception:
                fid = None
            self._persist_response_orphan(flow, pretty_url, req_id, fid)

        if request_info:
            try:
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
                _final = self._analyze_response_content(dict(flow.response.headers), flow.response.content)
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

                def _compute_delay_ms() -> int:
                    try:
                        import random
                        base_ms = int(delay_time) if delay_time else 0
                        jit_ms = int(jitter) if jitter else 0
                        _total_ms = base_ms
                        if distrib:
                            d = str(distrib).lower()
                            if d == 'uniform':
                                _total_ms += random.randint(0, jit_ms)
                            elif d == 'normal':
                                _total_ms = max(0, int(random.normalvariate(base_ms, max(1.0, jit_ms / 2))))
                            elif d == 'exponential':
                                lam = 1.0 / max(1, base_ms if base_ms > 0 else 1)
                                _total_ms = int(random.expovariate(lam))
                        elif jit_ms:
                            _total_ms += random.randint(0, jit_ms)
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
                                    _total_ms = val
                                    break
                        return max(0, int(_total_ms))
                    except Exception:
                        return 0

                total_ms = _compute_delay_ms()
                if total_ms > 0:
                    has_reply = (hasattr(flow, 'reply') and getattr(flow, 'reply', None) is not None and
                                 hasattr(getattr(flow, 'reply', None), 'take') and hasattr(getattr(flow, 'reply', None),
                                                                                           'send'))
                    flow.response.headers['X-Delay-Applied'] = 'true'
                    flow.response.headers['X-Delay-Effective'] = str(int(total_ms))

                    log_msg = f"响应延迟{' (降级)' if not has_reply else ''} {total_ms}ms → {flow.request.method} {flow.request.pretty_url}"
                    logger.info(log_msg)

                    if has_reply:
                        getattr(flow, 'reply').take()

                    # 阻塞延迟
                    time.sleep(total_ms / 1000.0)

                    if has_reply:
                        getattr(flow, 'reply').send()

                    request_info['response_time'] = (request_info.get('response_time') or 0) + (total_ms / 1000.0)

                # 计算最终响应信息（在延迟完成后再写入，以保持前后端一致）
                _final2 = self._analyze_response_content(dict(flow.response.headers), flow.response.content)
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

            except Exception as e:
                logger.exception("UProxier response() 处理异常，已写入兜底记录")
                self._record_response_stage_failure(request_info, e, flow)
                raise

    def error(self, flow: http.HTTPFlow) -> None:
        """处理错误"""
        logger.error(f"代理错误: {flow.error}")

        try:
            if flow.request.port in self.internal_web_ports:
                return
            if (flow.request.pretty_host, flow.request.port) in self.internal_targets:
                return
        except Exception:
            pass
        try:
            if not flow.metadata.get("uproxier_capture"):
                return
        except Exception:
            return

        target = self._find_traffic_row_for_flow(flow)
        if target is not None:
            target.update({
                'status': 'error',
                'error': str(flow.error),
                'error_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            try:
                self.web_interface.update_traffic_data(self.traffic_data, changed=target)
            except Exception as e2:
                logger.warning("error() 更新 Web 展示失败（仍尝试落盘）: %s", e2)
            self._maybe_persist(target, jsonl_phase='error')

    def _minimal_persist_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """主记录无法 JSON 序列化时，仅抽取关键字段兜底落盘。"""
        record = {
            k: v for k, v in record.items()
            if not (isinstance(k, str) and k.startswith("_"))
        }
        fid = record.get("flow_id")
        keys = (
            'id', 'method', 'url', 'host', 'port', 'path', 'scheme', 'timestamp',
            'status', 'error', 'error_timestamp',
            'handler_error', 'handler_error_timestamp',
            'response_status', 'response_timestamp',
            'terminated_before_response', 'persist_timestamp', 'jsonl_phase',
        )
        out: Dict[str, Any] = {
            'persist_minimal_fallback': True,
            'persist_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        for k in keys:
            if k in record:
                out[k] = record[k]
        if fid is not None:
            out['flow_id'] = fid
        return out

    def _emit_handler_failure_record(
        self, request_info: Dict[str, Any], exc: BaseException, *, status: str
    ) -> None:
        """请求阶段异常时仍入库、入 Web、落盘。"""
        request_info['status'] = status
        request_info['handler_error'] = f'{type(exc).__name__}: {exc}'
        request_info['handler_error_timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._traffic_state_lock:
            if request_info not in self.traffic_data:
                self.traffic_data.append(request_info)
        try:
            self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)
        except Exception as e2:
            logger.warning("更新 Web 展示失败（仍尝试落盘）: %s", e2)
        self._maybe_persist(request_info, jsonl_phase='request_handler_error')

    def _record_response_stage_failure(
        self, request_info: Dict[str, Any], exc: BaseException, flow: http.HTTPFlow
    ) -> None:
        """响应阶段异常时写入可诊断状态并落盘。"""
        request_info['status'] = 'response_handler_error'
        request_info['handler_error'] = f'{type(exc).__name__}: {exc}'
        request_info['handler_error_timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            if getattr(flow, 'response', None) is not None:
                request_info.setdefault('response_status', flow.response.status_code)
        except Exception:
            pass
        try:
            self.web_interface.update_traffic_data(self.traffic_data, changed=request_info)
        except Exception as e2:
            logger.warning("更新 Web 展示失败（仍尝试落盘）: %s", e2)
        self._maybe_persist(request_info, jsonl_phase='response_handler_error')

    def _maybe_persist(self, record: Optional[Dict[str, Any]], *, jsonl_phase: Optional[str] = None) -> None:
        if not record or not self.save_path:
            return
        payload = record_for_json_output(record, jsonl_phase=jsonl_phase)
        line: Optional[str] = None
        try:
            line = json.dumps(payload, ensure_ascii=False, default=str) + '\n'
        except (TypeError, ValueError) as e:
            logger.warning("请求记录 JSON 序列化失败，降级为最小字段落盘: %s", e)
            try:
                line = json.dumps(
                    self._minimal_persist_record(payload), ensure_ascii=False, default=str) + '\n'
            except Exception as e2:
                logger.error("最小字段记录仍无法序列化: %s", e2)
                return
        try:
            with open(self.save_path, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception as e:
            logger.error("保存请求数据失败: %s", e)

    def clear_traffic_state(self) -> None:
        with self._traffic_state_lock:
            self.traffic_data.clear()
            self.request_count = 0

    def flush_pending_records(self) -> None:
        """
        停止前兜底落盘仍处于 pending 状态的请求。
        说明：
        - 正常 completed/error 会在 response()/error() 中写盘；
        - 该方法仅补写未完成请求，尽量减少进程终止时的日志丢失。
        """
        if not self.save_path:
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._traffic_state_lock:
                pending_rows = [req for req in self.traffic_data if req.get('status') == 'pending']
            for req in pending_rows:
                rec = dict(req)
                rec.setdefault('terminated_before_response', True)
                rec.setdefault('persist_timestamp', now)
                self._maybe_persist(rec, jsonl_phase='terminated')
        except Exception as e:
            logger.warning(f"停止前补写 pending 请求失败: {e}")


class ProxyServer:
    """代理服务器主类"""

    def __init__(self, config_path: str = None, save_path: Optional[str] = None,
                 silent: bool = False, enable_https: Optional[bool] = None):
        self.config_path = config_path or default_config_path()
        self.save_path = save_path
        self.silent = silent
        self.enable_https_override = enable_https
        self.rules_engine = RulesEngine(self.config_path, silent=self.silent)
        self.cert_manager = CertificateManager(silent=self.silent)
        self.web_interface = WebInterface()
        self.addon = ProxyAddon(
            self.rules_engine,
            self.web_interface,
            save_path=save_path,
            silent=self.silent,
            config_path=self.config_path
        )
        self.web_interface.register_clear_traffic_handler(self.addon.clear_traffic_state)
        self.master = None
        self.is_running = False
        self._process = None  # 用于存储异步启动的进程对象

        self._setup_signal_handlers()

    def _setup_signal_handlers(self) -> None:
        """设置信号处理器，优雅地处理中断"""
        import signal

        def signal_handler(signum, frame):
            logger.info("接收到中断信号，正在停止代理服务器...")
            try:
                self.stop()
            except Exception as e:
                logger.warning(f"停止代理服务器时发生错误: {e}")
                import sys
                sys.exit(1)

        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        except (OSError, ValueError) as e:
            logger.warning(f"无法设置信号处理器: {e}")

    def _setup_ssl_callback_handling(self) -> None:
        """设置 SSL 回调异常处理，避免 KeyboardInterrupt 导致的崩溃"""
        try:
            import ssl
            import OpenSSL.SSL

            if hasattr(ssl.SSLContext, 'keylog_callback'):
                ssl.SSLContext.keylog_callback = None
                logger.debug("已禁用 SSL keylog 回调，避免 KeyboardInterrupt 崩溃")

        except ImportError:
            logger.debug("SSL 模块不可用，跳过 SSL 回调设置")
        except Exception as e:
            logger.warning(f"设置 SSL 回调处理失败: {e}")

    def start(self, port: int = 8001, web_port: int = 8002) -> None:
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
                    enable_https = bool(((cfg or {}).get('capture') or {}).get('enable_https', True))
            except Exception as _:
                enable_https = True

            # CLI 覆盖配置优先
            if self.enable_https_override is not None:
                enable_https = bool(self.enable_https_override)

            # 在静默模式下抑制所有日志输出
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
                # 抑制 Flask 的日志
                logging.getLogger('werkzeug').setLevel(logging.ERROR)
                logging.getLogger('flask').setLevel(logging.ERROR)
                # 抑制自己的日志输出
                logging.getLogger('uproxier').setLevel(logging.ERROR)

                # 设置环境变量抑制 mitmproxy 输出
                os.environ['MITMPROXY_QUIET'] = '1'
                os.environ['MITMPROXY_TERMLOG_VERBOSITY'] = 'error'
                os.environ['FLASK_DEBUG'] = '0'

            # 仅在启用 HTTPS 时才准备证书
            if enable_https:
                self.cert_manager.ensure_certificates()

            # 配置 mitmproxy（固定监听地址）
            host = DEFAULT_HOST
            # TLS 直通域名（不解密）：仅用 exclude.hosts，不捕获、不执行规则、也不解密
            # mitmproxy 的 ignore_hosts 匹配的是 "host:port"（如 apps.apple.com:443），需先转成正则再末尾允许 :port
            ignore_hosts: List[str] = []
            try:
                import yaml
                config_path = Path(self.config_path)
                if config_path.exists():
                    with open(config_path, 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f) or {}
                    exc = ((cfg or {}).get('capture') or {}).get('exclude') or {}
                    exc_hosts = exc.get('hosts')
                    raw = []
                    if isinstance(exc_hosts, list):
                        raw = [str(p) for p in exc_hosts if p]
                    elif exc_hosts:
                        raw = [str(exc_hosts)]
                    for p in raw:
                        # 先按 addon 同一逻辑把通配符/正则转成 host 正则，再为 ignore_hosts 加上 :port 后缀
                        regex_host = ProxyAddon._host_pattern_to_regex(p.rstrip())
                        base = regex_host.rstrip('$')
                        ignore_hosts.append(base + r'(:[0-9]+)?$')
            except Exception:
                ignore_hosts = []

            if enable_https:
                opts = options.Options(
                    listen_host=host,
                    listen_port=port,
                    confdir=str(self.cert_manager.cert_dir),
                    ssl_insecure=True,
                    http2=False,
                    ignore_hosts=ignore_hosts
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

            # 启动 Web 界面：固定绑定地址，确保局域网可访问
            web_host = DEFAULT_HOST
            # 注入运行时元信息供 /api/meta 使用
            try:
                # 计算用于展示的 web 主机（DEFAULT_HOST 时转为局域网 IP）
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
                    'proxy': {'host': DEFAULT_HOST, 'port': port},
                    'web': {'host': web_host, 'port': web_port, 'display_host': web_display_host},
                    'https_enabled': bool(enable_https),
                    'certificate': {'path': cert_path, 'sha256': cert_fingerprint}
                }
            except Exception:
                self.web_interface.server_meta = {}
            self.web_interface.start(web_port, host=web_host, silent=self.silent)

            # 启动代理服务器
            display_host = self._prefer_lan_host(host)
            logger.info(f"启动代理服务器: {display_host}:{port}")
            logger.info(f"Web 界面: http://{display_host}:{web_port}")
            logger.info(f"HTTPS 拦截: {'启用' if enable_https else '禁用（TLS 直通）'}")
            logger.info("按 Ctrl+C 停止服务器")

            self.is_running = True

            # 在事件循环中初始化并运行 DumpMaster
            async def _run_master():
                self._setup_ssl_callback_handling()

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
                    # 端口级跳过：即使 host 是 127.0.0.1/本机 IP/DEFAULT_HOST 变化，也不拦 Web 端口
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
            logger.info("正在停止代理服务器...")
        except Exception as e:
            logger.error(f"启动代理服务器失败: {e}")
            raise ProxyStartupError(f"代理服务器启动失败: {e}", port=port, web_port=web_port)
        finally:
            self.stop()

    def start_async(self, port: int = 8001, web_port: int = 8002) -> None:
        """异步启动代理服务器（非阻塞）。

        子进程默认静默且丢弃标准输出。可将环境变量 ``UPROXIER_LOG_FILE`` 设为路径，
        使子进程 stdout/stderr 追加写入该文件。
        """
        import subprocess
        import sys
        import os

        # 构建启动命令
        cmd = [sys.executable, "-m", "uproxier.cli", "start",
               "--port", str(port),
               "--web-port", str(web_port), "--config", self.config_path, "--silent"]

        if self.save_path:
            cmd.extend(["--save", self.save_path])

        if self.enable_https_override is not None:
            if self.enable_https_override:
                cmd.append("--enable-https")
            else:
                cmd.append("--disable-https")

        log_file = (os.environ.get("UPROXIER_LOG_FILE") or "").strip()
        log_fp = None
        popen_kw: Dict[str, Any] = {"stdin": subprocess.DEVNULL, "cwd": os.getcwd()}
        if log_file:
            log_fp = open(log_file, "a", encoding="utf-8", buffering=1)
            popen_kw["stdout"] = log_fp
            popen_kw["stderr"] = subprocess.STDOUT
        else:
            # 勿使用 stderr=PIPE 且长期不读，否则子进程写满管道会阻塞
            popen_kw["stdout"] = subprocess.DEVNULL
            popen_kw["stderr"] = subprocess.DEVNULL

        try:
            # 启动后台进程
            process = subprocess.Popen(cmd, **popen_kw)

            # 与前台 ``start()`` 不同：此前仅 sleep ~0.5s 即返回，子进程可能尚未 bind 端口，
            # 自动化紧接着打流量会出现「偶发未进代理 / 无 JSONL」。此处与 CLI ``--daemon`` 类似，
            # 轮询直至代理端口与 Web 端口均可连（或超时）。
            max_wait_s = 15.0
            poll_interval = 0.1
            deadline = time.monotonic() + max_wait_s
            ready = False

            while time.monotonic() < deadline:
                if process.poll() is not None:
                    out, err = process.communicate()
                    snippets: List[str] = []
                    if err:
                        snippets.append(err.decode(errors="replace").strip())
                    if out:
                        snippets.append(out.decode(errors="replace").strip())
                    if not snippets and log_file:
                        snippets.append(f"请查看日志文件: {log_file}")
                    if not snippets:
                        snippets.append(
                            "无捕获的 stderr/stdout（默认丢弃子进程输出；可设 UPROXIER_LOG_FILE）"
                        )
                    error_msg = " | ".join(s for s in snippets if s)
                    raise ProxyStartupError(f"后台进程启动失败: {error_msg}", port=port, web_port=web_port)

                if _local_port_accepting_connections(port) and _local_port_accepting_connections(web_port):
                    ready = True
                    break

                time.sleep(poll_interval)

            if not ready:
                try:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=3)
                except Exception:
                    pass
                raise ProxyStartupError(
                    f"后台进程启动超时（{max_wait_s}s 内 {port}/{web_port} 端口未就绪）。"
                    f"若 CPU 较慢可适当延后测试流量。",
                    port=port, web_port=web_port,
                )

            # 设置运行状态
            self.is_running = True
            self._process = process  # 保存进程引用，用于停止

            logger.info(f"服务器已在后台启动 (PID: {process.pid})")
            logger.info(f"代理地址: {DEFAULT_HOST}:{port}")
            logger.info(f"Web 界面: http://{DEFAULT_HOST}:{web_port}")

            return process

        except Exception as e:
            logger.error(f"启动失败: {e}")
            raise
        finally:
            if log_fp is not None:
                try:
                    log_fp.close()
                except Exception:
                    pass

    def stop(self) -> None:
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
                logger.error(f"停止进程失败: {e}")
            finally:
                self._process = None

        # 安全地停止 master，避免事件循环关闭错误
        if self.master:
            try:
                self.master.shutdown()
            except RuntimeError as e:
                if "Event loop is closed" in str(e):
                    logger.debug("事件循环已关闭，跳过 master.shutdown()")
                else:
                    logger.warning(f"停止 master 时发生错误: {e}")
            except Exception as e:
                logger.warning(f"停止 master 时发生异常: {e}")

        # 在 master 停止后兜底补写仍未完成的请求，尽量减少日志丢失
        if self.addon:
            try:
                self.addon.flush_pending_records()
            except Exception as e:
                logger.warning(f"补写 pending 请求失败: {e}")

        if self.web_interface:
            try:
                self.web_interface.stop()
            except Exception as e:
                logger.warning(f"停止 web 界面时发生错误: {e}")

        self.is_running = False
        logger.info("代理服务器已停止")

    def _prefer_lan_host(self, bind_host: str) -> str:
        """优先返回局域网 IP，失败回退 127.0.0.1"""
        return get_display_host(bind_host, "127.0.0.1")

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
    parser.add_argument("--port", type=int, default=8080, help="代理服务器端口")
    parser.add_argument("--web-port", type=int, default=8081, help="Web 界面端口")
    parser.add_argument("--config", default=None, help="配置文件路径")
    parser.add_argument("--log-level", default="INFO", help="日志级别")

    args = parser.parse_args()

    # 启动代理服务器
    config_path = args.config or default_config_path()
    proxy = ProxyServer(config_path)
    proxy.start(args.port, args.web_port)
