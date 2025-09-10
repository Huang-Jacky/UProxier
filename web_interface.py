#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Dict, List, Any, Optional

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask import Response
from flask import stream_with_context
from flask_cors import CORS

from version import get_version, get_author

logger = logging.getLogger(__name__)


class WebInterface:
    """Web 界面管理器"""

    def __init__(self):
        from importlib.resources import files as _files
        templates_dir = _files('uproxier') / 'templates'
        template_folder = str(templates_dir)
        self.app = Flask(__name__, template_folder=template_folder)
        CORS(self.app)
        self.traffic_data = []
        self.server_thread = None
        self.is_running = False
        self._traffic_subscribers: List[Queue] = []
        self._stats_subscribers: List[Queue] = []
        self.server_meta: Dict[str, Any] = {}
        # 小体积二进制预览缓存：{request_id: {data: bytes, mime: str}}
        self._binary_previews: Dict[int, Dict[str, Any]] = {}
        # 预览缓存容量控制（约 32MB）
        self._binary_previews_bytes: int = 0
        self._binary_previews_max_bytes: int = 32 * 1024 * 1024

        # 注册路由
        self.register_routes()

    def register_routes(self):
        """注册 Flask 路由"""

        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/api/traffic')
        def get_traffic():
            """获取流量数据"""
            limit = request.args.get('limit', 100, type=int)
            filtered_data = self.traffic_data[-limit:] if limit > 0 else self.traffic_data
            return jsonify({
                'data': filtered_data,
                'total': len(self.traffic_data),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

        @self.app.route('/api/export')
        def export_traffic():
            """导出当前内存中的流量数据。支持 format=json|jsonl|csv，支持 limit。"""
            try:
                fmt = (request.args.get('format') or 'json').lower()
                limit = request.args.get('limit', type=int)
                data = self.traffic_data if not limit or limit <= 0 else self.traffic_data[-limit:]
                # 为避免过大导出，设置一个导出上限（默认 10000 条）
                if len(data) > 10000:
                    data = data[-10000:]
                if fmt == 'jsonl':
                    from io import BytesIO
                    buf = BytesIO()
                    for rec in data:
                        line = json.dumps(rec, ensure_ascii=False) + '\n'
                        buf.write(line.encode('utf-8'))
                    buf.seek(0)
                    return Response(buf, mimetype='application/jsonl', headers={
                        'Content-Disposition': 'attachment; filename="traffic.jsonl"'
                    })
                elif fmt == 'csv':
                    import csv
                    from io import StringIO
                    # 扩展导出字段，便于离线分析
                    fields = [
                        'id', 'timestamp', 'method', 'url', 'host',
                        'request_body',
                        'status', 'response_status', 'response_time',
                        'content_size', 'response_content_size',
                        # 规则与延迟观测
                        'rule_names', 'delay_applied', 'delay_effective_ms',
                        # 请求侧标记
                        'is_req_binary', 'is_req_streaming', 'is_req_large',
                        # 响应侧标记
                        'is_rsp_binary', 'is_rsp_streaming', 'is_rsp_large',
                        # 响应头摘要
                        'rsp_content_type', 'rsp_transfer_encoding', 'rsp_content_length'
                    ]

                    def _flat(rec: Dict[str, Any]) -> Dict[str, Any]:
                        try:
                            rh = rec.get('response_headers') or {}

                            # 大小写不敏感取头
                            def _h(name: str) -> Optional[str]:
                                if not isinstance(rh, dict):
                                    return None
                                for k, v in rh.items():
                                    if str(k).lower() == name.lower():
                                        return v
                                return None

                            rule_names = _h('X-Rule-Name') or ''
                            delay_applied = (_h('X-Delay-Applied') or '').lower() == 'true'
                            delay_effective = _h('X-Delay-Effective') or ''
                        except Exception:
                            rule_names = ''
                            delay_applied = False
                            delay_effective = ''

                        return {
                            'id': rec.get('id'),
                            'timestamp': rec.get('timestamp') or rec.get('response_timestamp'),
                            'method': rec.get('method'),
                            'url': rec.get('url'),
                            'host': rec.get('host'),
                            'request_body': (rec.get('modified_content') if rec.get('modified_content') not in (
                                None, '') else rec.get('content')),
                            'status': rec.get('status'),
                            'response_status': rec.get('response_status'),
                            'response_time': rec.get('response_time'),
                            'content_size': rec.get('content_size'),
                            'response_content_size': rec.get('response_content_size'),
                            # 新增观测字段
                            'rule_names': rule_names,
                            'delay_applied': delay_applied,
                            'delay_effective_ms': delay_effective,
                            'is_req_binary': rec.get('is_binary'),
                            'is_req_streaming': rec.get('is_streaming'),
                            'is_req_large': rec.get('is_large_file'),
                            'is_rsp_binary': rec.get('is_response_binary'),
                            'is_rsp_streaming': rec.get('is_response_streaming'),
                            'is_rsp_large': rec.get('is_response_large_file'),
                            'rsp_content_type': rec.get('response_content_type') or rec.get('response_headers', {}).get(
                                'Content-Type'),
                            'rsp_transfer_encoding': rec.get('response_transfer_encoding'),
                            'rsp_content_length': rec.get('response_content_length'),
                        }

                    sio = StringIO()
                    writer = csv.DictWriter(sio, fieldnames=fields)
                    writer.writeheader()
                    for rec in data:
                        writer.writerow(_flat(rec))
                    return Response(sio.getvalue(), mimetype='text/csv; charset=utf-8', headers={
                        'Content-Disposition': 'attachment; filename="traffic.csv"'
                    })
                else:  # json
                    return Response(json.dumps(data, ensure_ascii=False), mimetype='application/json', headers={
                        'Content-Disposition': 'attachment; filename="traffic.json"'
                    })
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/stats')
        def get_stats():
            """获取统计信息"""
            completed_requests = [req for req in self.traffic_data if req.get('status') == 'completed']
            error_requests = [req for req in self.traffic_data if req.get('status') == 'error']

            # 计算响应时间统计
            response_times = [req.get('response_time', 0) for req in completed_requests]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0

            return jsonify({
                'total_requests': len(self.traffic_data),
                'completed_requests': len(completed_requests),
                'error_requests': len(error_requests),
                'pending_requests': len([req for req in self.traffic_data if req.get('status') == 'pending']),
                'avg_response_time': round(avg_response_time, 3),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

        @self.app.route('/api/stream/traffic')
        def stream_traffic():
            def gen():
                q: Queue = Queue(maxsize=16)
                self._traffic_subscribers.append(q)
                try:
                    # 首次推送最近数据
                    snapshot = {'type': 'traffic', 'data': self.traffic_data[-100:]}
                    yield f"data: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
                    # 持续消费，带心跳，避免中间设备/浏览器断开
                    while True:
                        try:
                            item = q.get(timeout=10)
                            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                        except Exception:
                            # 心跳注释行（不触发 onmessage）
                            yield ": keepalive\n\n"
                finally:
                    try:
                        self._traffic_subscribers.remove(q)
                    except ValueError:
                        pass

            return Response(
                stream_with_context(gen()),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'X-Accel-Buffering': 'no'
                }
            )

        @self.app.route('/api/meta')
        def get_meta():
            try:
                meta = dict(self.server_meta or {})
                meta['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                meta['version'] = get_version()
                meta['author'] = get_author()
                return jsonify(meta)
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/stream/stats')
        def stream_stats():
            def gen():
                q: Queue = Queue(maxsize=16)
                self._stats_subscribers.append(q)
                try:
                    # 首次推送当前统计
                    q.put(self._current_stats_payload())
                    while True:
                        try:
                            item = q.get(timeout=10)
                            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                        except Exception:
                            yield ": keepalive\n\n"
                finally:
                    try:
                        self._stats_subscribers.remove(q)
                    except ValueError:
                        pass

            return Response(
                stream_with_context(gen()),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'X-Accel-Buffering': 'no'
                }
            )

        @self.app.route('/api/clear', methods=['POST'])
        def clear_traffic():
            """清空流量数据"""
            try:
                # 清空流量数据
                self.traffic_data.clear()

                # 通知代理服务器清空数据（如果可能的话）
                # 这里可以添加与代理服务器的通信逻辑

                # 清空预览缓存
                self._binary_previews.clear()
                # 重置预览缓存字节计数，避免内存统计漂移
                try:
                    self._binary_previews_bytes = 0
                except Exception:
                    pass

                # 广播一次空的流量与统计，确保状态栏同步归零
                try:
                    self.update_traffic_data(self.traffic_data)
                except Exception:
                    pass

                return jsonify({'message': '流量数据已清空', 'success': True})
            except Exception as e:
                return jsonify({'message': f'清空失败: {str(e)}', 'success': False}), 500

        @self.app.route('/api/request/<int:request_id>')
        def get_request_detail(request_id):
            """获取请求详情"""
            for req in self.traffic_data:
                if req.get('id') == request_id:
                    try:
                        # 避免返回过大的原始内容字段
                        data = dict(req)
                        if 'response_original_content' in data:
                            data.pop('response_original_content', None)
                        return jsonify(data)
                    except Exception:
                        return jsonify(req)
            return jsonify({'error': '请求不存在'}), 404

        @self.app.route('/api/preview/<int:request_id>')
        def get_preview(request_id: int):
            """返回图片/视频等小体积内容的内存预览。"""
            try:
                meta = self._binary_previews.get(request_id)
                if not meta:
                    return jsonify({'error': '预览不存在'}), 404
                data = meta.get('data')
                mime = meta.get('mime') or 'application/octet-stream'
                if not data:
                    return jsonify({'error': '内容为空'}), 404
                return Response(data, mimetype=mime, headers={'Cache-Control': 'no-store'})
            except Exception as e:
                return jsonify({'error': f'读取预览失败: {e}'}), 500

        @self.app.route('/api/hosts')
        def get_hosts():
            """返回可用于二维码的可访问基址列表（含局域网地址）"""
            try:
                import socket
                # 从请求推断
                host = request.host.split('/')[0]
                if ':' in host:
                    req_host, req_port = host.split(':', 1)
                else:
                    req_host, req_port = host, ''
                scheme = request.scheme

                bases = set()
                if req_port:
                    bases.add(f"{scheme}://{req_host}:{req_port}")
                else:
                    bases.add(f"{scheme}://{req_host}")

                # 获取首选局域网 IP
                lan_ip = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    lan_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass
                if lan_ip:
                    if req_port:
                        bases.add(f"{scheme}://{lan_ip}:{req_port}")
                    else:
                        bases.add(f"{scheme}://{lan_ip}")

                # 常见回环别名
                if req_port:
                    bases.add(f"{scheme}://localhost:{req_port}")
                    bases.add(f"{scheme}://127.0.0.1:{req_port}")
                else:
                    bases.add(f"{scheme}://localhost")
                    bases.add(f"{scheme}://127.0.0.1")

                return jsonify({
                    'bases': list(bases),
                    'preferred': lan_ip
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/cert/download/<fmt>')
        def download_cert(fmt: str):
            """下载 CA 证书，支持 pem(PEM) 与 cer(DER)。"""
            try:
                fmt_l = fmt.lower()
                cert_dir = Path.home() / '.uproxier'
                if not cert_dir.exists():
                    cert_dir = Path.home() / '.mitmproxy'
                if fmt_l == 'pem':
                    filename = 'mitmproxy-ca-cert.pem'
                    download_name = 'uproxier-ca.pem'
                    mimetype = 'application/x-pem-file'
                elif fmt_l == 'cer':
                    filename = 'mitmproxy-ca-cert.der'
                    download_name = 'uproxier-ca.cer'
                    mimetype = 'application/pkix-cert'
                else:
                    return jsonify({'error': '仅支持 pem 或 cer'}), 400
                filepath = cert_dir / filename
                if not filepath.exists():
                    return jsonify({'error': f'证书文件不存在: {filepath}'}), 404
                resp = send_from_directory(
                    directory=str(cert_dir),
                    path=filename,
                    as_attachment=True,
                    download_name=download_name
                )
                try:
                    resp.headers['Content-Type'] = mimetype
                except Exception:
                    pass
                return resp
            except Exception as e:
                return jsonify({'error': f'证书下载失败: {e}'}), 500

    def update_traffic_data(self, traffic_data: List[Dict[str, Any]], changed: Optional[Dict[str, Any]] = None):
        """更新流量数据，并优先推送本次变更的那条记录（避免只推送最后一条导致行未刷新）。"""

        # 将可能携带的 base64 预览转为内存缓存 + URL，避免前端大体积 payload
        def _materialize_preview(rec: Dict[str, Any]) -> Dict[str, Any]:
            try:
                rid = rec.get('id')
                b64 = rec.pop('response_preview_b64', None)
                mime = rec.get('response_preview_mime') or ''
                if rid and b64 and mime:
                    import base64
                    data = base64.b64decode(b64)
                    self._binary_previews[int(rid)] = {'data': data, 'mime': mime}
                    rec['response_preview_url'] = f"/api/preview/{rid}"
                return rec
            except Exception:
                return rec

        self.traffic_data = [_materialize_preview(dict(r)) for r in traffic_data]
        # 广播最新片段（最近一条或最近100条）与统计
        try:
            if changed is not None:
                payload = {'type': 'traffic', 'data': [_materialize_preview(dict(changed))]}
            else:
                payload = {'type': 'traffic', 'data': self.traffic_data[-1:]} if self.traffic_data else {
                    'type': 'traffic', 'data': []}
            for q in list(self._traffic_subscribers):
                if not q.full():
                    q.put(payload)
        except Exception:
            pass
        try:
            stats = self._current_stats_payload()
            for q in list(self._stats_subscribers):
                if not q.full():
                    q.put(stats)
        except Exception:
            pass

    def register_binary_preview(self, request_id: int, data: bytes, mime: str) -> str:
        """注册小体积二进制预览到内存缓存，并返回可访问 URL。"""
        try:
            rid = int(request_id)
            size = len(data) if data else 0
            # 若已有同 id，先扣除旧值
            old = self._binary_previews.get(rid)
            if old and isinstance(old.get('data'), (bytes, bytearray)):
                try:
                    self._binary_previews_bytes -= len(old.get('data') or b'')
                except Exception:
                    pass

            # 逐出策略：先入先出原则按 id 插入顺序简单逐出，直到不超上限
            def _evict_until_fit(add_bytes: int):
                try:
                    while self._binary_previews_bytes + add_bytes > self._binary_previews_max_bytes and self._binary_previews:
                        # 弹出最早插入的一个
                        oldest_key = next(iter(self._binary_previews.keys()))
                        ent = self._binary_previews.pop(oldest_key, None)
                        if ent and isinstance(ent.get('data'), (bytes, bytearray)):
                            self._binary_previews_bytes -= len(ent.get('data') or b'')
                except Exception:
                    pass

            _evict_until_fit(size)
            self._binary_previews[rid] = {'data': data, 'mime': mime or 'application/octet-stream'}
            self._binary_previews_bytes += size
            return f"/api/preview/{int(request_id)}"
        except Exception:
            return ""

    def _current_stats_payload(self) -> Dict[str, Any]:
        completed_requests = [req for req in self.traffic_data if req.get('status') == 'completed']
        error_requests = [req for req in self.traffic_data if req.get('status') == 'error']
        response_times = [req.get('response_time', 0) for req in completed_requests]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        return {
            'type': 'stats',
            'data': {
                'total_requests': len(self.traffic_data),
                'completed_requests': len(completed_requests),
                'error_requests': len(error_requests),
                'pending_requests': len([req for req in self.traffic_data if req.get('status') == 'pending']),
                'avg_response_time': round(avg_response_time, 3),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }

    def start(self, port: int = 8081, host: str = "127.0.0.1", silent: bool = False):
        """启动 Web 界面"""
        if self.is_running:
            return

        def run_server():
            try:
                # 关闭 Flask 的访问日志
                import logging
                log = logging.getLogger('werkzeug')
                log.setLevel(logging.ERROR)

                # 在静默模式下抑制更多日志
                if silent:
                    # 抑制 Flask 的所有输出
                    import os
                    os.environ['FLASK_DEBUG'] = '0'  # 使用新的环境变量
                    # 抑制更多日志
                    logging.getLogger('werkzeug').setLevel(logging.ERROR)
                    logging.getLogger('flask').setLevel(logging.ERROR)
                    logging.getLogger('urllib3').setLevel(logging.ERROR)

                    # 重定向 Flask 的输出
                    from contextlib import redirect_stdout, redirect_stderr
                    with open(os.devnull, 'w') as devnull:
                        with redirect_stdout(devnull), redirect_stderr(devnull):
                            self.app.run(host=host, port=port, debug=False, use_reloader=False)
                else:
                    self.app.run(host=host, port=port, debug=False, use_reloader=False)
            except Exception as e:
                if not silent:
                    logger.error(f"Web 界面启动失败: {e}")

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.is_running = True

        if not silent:
            display_host = host
            try:
                if host in ("0.0.0.0", "::"):
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    display_host = s.getsockname()[0]
                    s.close()
            except Exception:
                pass
            logger.info(f"Web 界面已启动: http://{display_host}:{port}")

    def stop(self):
        """停止 Web 界面"""
        self.is_running = False
