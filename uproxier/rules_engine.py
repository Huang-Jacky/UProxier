#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any, DefaultDict

import yaml
from mitmproxy import http

from uproxier.action_processors import ActionProcessorManager
from uproxier.exceptions import ConfigInheritanceError, RuleValidationError

logger = logging.getLogger(__name__)


class Rule:
    """规则基类"""

    def __init__(self, rule_config: Dict[str, Any], config_dir: Optional[str] = None):
        self.name = rule_config.get('name', 'unnamed')
        self.enabled = rule_config.get('enabled', True)
        self.priority = rule_config.get('priority', 0)
        self.config_dir = config_dir
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

        self.action_manager = ActionProcessorManager(config_dir)
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

    def get_host_key(self) -> Optional[str]:
        """获取规则的主机键，用于索引优化"""
        return getattr(self, '_host_key', None)

    def get_path_prefix(self) -> Optional[str]:
        """获取规则的路径前缀，用于索引优化"""
        return getattr(self, '_path_prefix', None)

    def apply_request_actions(self, request: http.Request) -> Optional[http.Request]:
        """应用请求动作（仅通用 DSL 的 request_pipeline）"""
        modified = False

        for step in self.request_pipeline:
            action = step.get('action')
            params = step.get('params', {})

            # 使用动作处理器处理
            if self.action_manager.process_request_action(action, request, params):
                modified = True

        return request if modified else None

    def apply_response_actions(self, response: http.Response) -> Optional[http.Response]:
        """应用响应动作"""
        modified = False
        for step in self.response_pipeline:
            action = step.get('action')
            params = step.get('params', {})

            # 使用动作处理器处理
            if self.action_manager.process_response_action(action, response, params):
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

    def __init__(self, config_path: str = None, silent: bool = False):
        self.config_path = config_path or default_config_path()
        self.silent = silent
        self.rules: List[Rule] = []

        # 初始化索引
        self._host_index: DefaultDict[str, List[Rule]] = defaultdict(list)
        self._path_index: DefaultDict[str, List[Rule]] = defaultdict(list)
        self._generic_rules: List[Rule] = []

        self.load_rules()

    def load_rules(self) -> None:
        """从配置文件加载规则，支持继承"""
        try:
            config_path = Path(self.config_path)
            if not config_path.exists():
                self.create_default_config()

            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if 'extends' in config:
                config = self._resolve_extends(config, config_path.parent)

            self.rules = []
            config_dir = str(config_path.parent)
            for idx, rule_config in enumerate(config.get('rules', [])):
                self._validate_rule_config(rule_config, idx)
                rule = Rule(rule_config, config_dir)
                self.rules.append(rule)

            self.rules.sort(key=lambda x: x.priority, reverse=True)

            # 构建索引：host_key -> [Rule]，path_prefix -> [Rule]，以及通用列表
            self._host_index.clear()
            self._path_index.clear()
            self._generic_rules.clear()

            for r in self.rules:
                inserted = False
                host_key = r.get_host_key()
                if host_key:
                    self._host_index[host_key].append(r)
                    inserted = True
                path_prefix = r.get_path_prefix()
                if path_prefix:
                    self._path_index[path_prefix].append(r)
                    inserted = True
                if not inserted:
                    self._generic_rules.append(r)

            if not self.silent:
                enabled_count = sum(1 for r in self.rules if getattr(r, 'enabled', True))
                logger.info(f"加载了 {len(self.rules)} 条规则（启用 {enabled_count} 条）")

        except (ConfigInheritanceError, RuleValidationError) as e:
            # 配置错误：直接抛出，让调用者处理
            raise
        except Exception as e:
            # 其他错误：可能是临时问题，可以继续运行
            if not self.silent:
                logger.error(f"加载规则失败: {e}")
            self.rules = []

    def create_default_config(self) -> None:
        """创建默认配置文件"""
        default_config = {
            'capture': {
                'include': {
                    'hosts': ['.*']  # 默认捕获所有请求
                },
                'enable_streaming': False,
                'enable_large_files': False,
                'large_file_threshold': 1048576,
                'save_binary_content': False,
                'enable_https': True
            },
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

    def _resolve_extends(self, config: Dict, current_dir: Path) -> Dict:
        """解析配置文件继承"""
        if 'extends' not in config:
            return config

        extends_file = config['extends']

        if not Path(extends_file).is_absolute():
            extends_file = current_dir / extends_file

        extends_file = Path(extends_file).resolve()

        if not extends_file.exists():
            suggestions = [
                "检查继承文件路径是否正确",
                "确认相对路径层级 (../ 数量)",
                "验证文件是否真实存在",
                "使用绝对路径避免路径问题"
            ]
            raise ConfigInheritanceError(
                f"继承配置文件不存在: {extends_file}",
                extends_file=config['extends'],
                current_file=str(current_dir),
                resolved_path=str(extends_file),
                suggestions=suggestions
            )

        with open(extends_file, 'r', encoding='utf-8') as f:
            base_config = yaml.safe_load(f)

        base_config = self._resolve_extends(base_config, Path(extends_file).parent)

        merged_config = self._merge_configs(base_config, config, Path(extends_file).parent, current_dir)

        return merged_config

    def _merge_configs(self, base: Dict, current: Dict, base_dir: Path, current_dir: Path) -> Dict:
        """合并配置，当前配置优先，处理路径标准化"""
        merged = base.copy()

        if 'rules' in merged:
            for rule in merged['rules']:
                if 'response_pipeline' in rule:
                    for action in rule['response_pipeline']:
                        if action.get('action') == 'mock_response' and 'file' in action.get('params', {}):
                            file_path = action['params']['file']
                            if not Path(file_path).is_absolute():
                                # 将基础配置中的相对路径转换为相对于当前配置文件的路径
                                base_file_path = base_dir / file_path
                                relative_path = os.path.relpath(base_file_path, current_dir)
                                action['params']['file'] = relative_path

        if 'capture' in current:
            if 'capture' in merged:
                merged['capture'].update(current['capture'])
            else:
                merged['capture'] = current['capture']

        if 'rules' in current:
            if 'rules' not in merged:
                merged['rules'] = []
            merged['rules'].extend(current['rules'])

        merged.pop('extends', None)

        return merged

    def _export_match(self, conds: Dict[str, Any]) -> Dict[str, Any]:
        """将内部 match_config(host_pattern/url_pattern/method) 回写为 DSL 的 match(host/path/method)"""
        out: Dict[str, Any] = {}
        hp = conds.get('host_pattern')
        up = conds.get('url_pattern')
        if isinstance(hp, str):
            out['host'] = hp
        if isinstance(up, str):
            out['path'] = up
        m = conds.get('method')
        if isinstance(m, str):
            out['method'] = m
        return out

    def _validate_rule_config(self, rule_config: Dict[str, Any], idx: int) -> None:
        """验证规则配置
        
        Args:
            rule_config: 规则配置字典
            idx: 规则索引
            
        Raises:
            RuleValidationError: 规则配置验证失败时抛出
        """
        name = rule_config.get('name', f'rule_{idx}')

        allowed_top = {'name', 'enabled', 'priority', 'stop_after_match', 'match', 'request_pipeline',
                       'response_pipeline'}
        unknown = set(rule_config.keys()) - allowed_top
        if unknown:
            raise RuleValidationError(
                f"规则存在不支持的顶层字段: {sorted(list(unknown))}",
                rule_name=name,
                rule_index=idx,
                field='top_level'
            )

        match = rule_config.get('match', {})
        if not isinstance(match, dict):
            raise RuleValidationError(
                "规则的 match 必须为对象",
                rule_name=name,
                rule_index=idx,
                field='match'
            )

        for key in ('request_pipeline', 'response_pipeline'):
            pipeline = rule_config.get(key, [])
            if pipeline is None:
                continue
            if not isinstance(pipeline, list):
                raise RuleValidationError(
                    f"规则的 {key} 必须为数组",
                    rule_name=name,
                    rule_index=idx,
                    field=key
                )
            for i, step in enumerate(pipeline):
                if not isinstance(step, dict):
                    raise RuleValidationError(
                        f"规则的 {key}[{i}] 必须为对象",
                        rule_name=name,
                        rule_index=idx,
                        field=f"{key}[{i}]"
                    )
                if 'action' not in step:
                    raise RuleValidationError(
                        f"规则的 {key}[{i}] 缺少 action 字段",
                        rule_name=name,
                        rule_index=idx,
                        field=f"{key}[{i}].action"
                    )
                action = step.get('action')
                params = step.get('params', {})
                if params is not None and not isinstance(params, (dict, str, int, float, list)):
                    raise RuleValidationError(
                        f"规则的 {key}[{i}].params 类型不支持",
                        rule_name=name,
                        rule_index=idx,
                        field=f"{key}[{i}].params"
                    )
                req_actions = {'set_header', 'remove_header', 'rewrite_url', 'redirect', 'replace_body',
                               'short_circuit', 'set_query_param', 'set_body_param'}
                res_actions = {'set_status', 'set_header', 'remove_header', 'replace_body', 'replace_body_json',
                               'mock_response', 'delay', 'short_circuit', 'conditional'}
                valid = req_actions if key == 'request_pipeline' else res_actions
                if action not in valid:
                    suggestions = [a for a in valid if a.startswith(action[:3])] if action else []
                    raise RuleValidationError(
                        f"规则的 {key}[{i}].action 不支持: {action}",
                        rule_name=name,
                        rule_index=idx,
                        field=f"{key}[{i}].action",
                        suggestions=suggestions
                    )

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
            except Exception as e:
                if not self.silent:
                    logger.warning(f"规则匹配失败 {rule.name}: {e}")
                continue

            try:
                modified_response = rule.apply_response_actions(response)
                if modified_response is not None:
                    try:
                        existing = modified_response.headers.get('X-Rule-Name') or ''
                        if existing:
                            if rule.name not in [s.strip() for s in existing.split(',')]:
                                modified_response.headers['X-Rule-Name'] = existing + ',' + rule.name
                        else:
                            modified_response.headers['X-Rule-Name'] = rule.name
                    except Exception as e:
                        if not self.silent:
                            logger.warning(f"设置规则名称头失败 {rule.name}: {e}")
                    result_response = modified_response
                    if getattr(rule, 'stop_after_match', False):
                        break
            except Exception as e:
                if not self.silent:
                    logger.error(f"规则执行失败 {rule.name}: {e}")
                # 继续执行其他规则，不因单个规则失败而中断
                continue
        return result_response


def get_uproxier_dir() -> Path:
    """获取 UProxier 主目录"""
    home_dir = Path.home()
    uproxier_dir = home_dir / '.uproxier'
    uproxier_dir.mkdir(exist_ok=True)
    return uproxier_dir


def default_config_path() -> str:
    """获取默认配置文件路径，保存在用户主目录"""
    uproxier_dir = get_uproxier_dir()
    return str(uproxier_dir / 'config.yaml')
