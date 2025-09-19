#!/usr/bin/env python3
"""
UProxier 配置分析工具
用于分析规则文件，包括继承关系和文件依赖
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml


class ConfigValidator:
    """配置验证器 - 提供配置验证和默认值管理功能"""

    def __init__(self):
        self.validation_errors = []
        self.validation_warnings = []

    def validate_config(self, config: dict, config_path: str = None) -> Dict[str, Any]:
        """验证配置文件的完整性和正确性"""
        self.validation_errors = []
        self.validation_warnings = []

        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # 验证基本结构
        self._validate_basic_structure(config)

        # 验证 capture 配置
        if 'capture' in config:
            self._validate_capture_config(config['capture'])

        # 验证 rules 配置
        if 'rules' in config:
            self._validate_rules_config(config['rules'], config_path)

        # 验证继承配置
        if 'extends' in config:
            self._validate_extends_config(config['extends'], config_path)

        result['errors'] = self.validation_errors
        result['warnings'] = self.validation_warnings
        result['valid'] = len(self.validation_errors) == 0

        return result

    def _validate_basic_structure(self, config: dict) -> None:
        """验证基本配置结构"""
        if not isinstance(config, dict):
            self.validation_errors.append("配置文件必须是字典格式")
            return

        # 检查必需的顶层字段
        required_fields = ['capture', 'rules']
        for field in required_fields:
            if field not in config:
                self.validation_errors.append(f"缺少必需的配置字段: {field}")

        # 检查未知字段
        allowed_fields = {'capture', 'rules', 'extends'}
        for field in config.keys():
            if field not in allowed_fields:
                self.validation_warnings.append(f"未知的配置字段: {field}")

    def _validate_capture_config(self, capture: dict) -> None:
        """验证 capture 配置"""
        if not isinstance(capture, dict):
            self.validation_errors.append("capture 配置必须是字典格式")
            return

        # 验证布尔字段
        boolean_fields = ['enable_streaming', 'enable_large_files', 'save_binary_content', 'enable_https']
        for field in boolean_fields:
            if field in capture and not isinstance(capture[field], bool):
                self.validation_errors.append(f"capture.{field} 必须是布尔值")

        # 验证数值字段
        numeric_fields = ['large_file_threshold', 'binary_preview_max_bytes']
        for field in numeric_fields:
            if field in capture:
                if not isinstance(capture[field], (int, float)) or capture[field] < 0:
                    self.validation_errors.append(f"capture.{field} 必须是非负数")

        # 验证 include/exclude 配置
        for filter_type in ['include', 'exclude']:
            if filter_type in capture:
                self._validate_filter_config(capture[filter_type], f"capture.{filter_type}")

    def _validate_filter_config(self, filter_config: dict, path: str) -> None:
        """验证过滤配置"""
        if not isinstance(filter_config, dict):
            self.validation_errors.append(f"{path} 必须是字典格式")
            return

        allowed_fields = {'hosts', 'paths', 'methods'}
        for field in filter_config.keys():
            if field not in allowed_fields:
                self.validation_warnings.append(f"{path}.{field} 不是标准的过滤字段")

        # 验证数组字段
        for field in ['hosts', 'paths', 'methods']:
            if field in filter_config:
                if not isinstance(filter_config[field], list):
                    self.validation_errors.append(f"{path}.{field} 必须是数组")
                else:
                    for item in filter_config[field]:
                        if not isinstance(item, str):
                            self.validation_errors.append(f"{path}.{field} 中的项目必须是字符串")

    def _validate_rules_config(self, rules: list, config_path: str = None) -> None:
        """验证 rules 配置"""
        if not isinstance(rules, list):
            self.validation_errors.append("rules 必须是数组")
            return

        if len(rules) == 0:
            self.validation_warnings.append("rules 数组为空")

        for i, rule in enumerate(rules):
            self._validate_single_rule(rule, i, config_path)

    def _validate_single_rule(self, rule: dict, index: int, config_path: str = None) -> None:
        """验证单个规则"""
        if not isinstance(rule, dict):
            self.validation_errors.append(f"规则 {index + 1} 必须是字典格式")
            return

        # 验证必需字段
        if 'name' not in rule:
            self.validation_errors.append(f"规则 {index + 1} 缺少 name 字段")

        if 'match' not in rule:
            self.validation_errors.append(f"规则 {index + 1} 缺少 match 字段")

        # 验证 match 配置
        if 'match' in rule:
            self._validate_match_config(rule['match'], f"规则 {index + 1}.match")

        # 验证 pipeline 配置
        for pipeline in ['request_pipeline', 'response_pipeline']:
            if pipeline in rule:
                self._validate_pipeline_config(rule[pipeline], f"规则 {index + 1}.{pipeline}", config_path)

        # 验证其他字段
        allowed_fields = {'name', 'match', 'request_pipeline', 'response_pipeline', 'enabled', 'priority',
                          'stop_after_match'}
        for field in rule.keys():
            if field not in allowed_fields:
                self.validation_warnings.append(f"规则 {index + 1} 包含未知字段: {field}")

    def _validate_match_config(self, match: dict, path: str) -> None:
        """验证匹配配置"""
        if not isinstance(match, dict):
            self.validation_errors.append(f"{path} 必须是字典格式")
            return

        # 验证匹配字段
        match_fields = ['host', 'path', 'method', 'headers', 'query', 'body', 'url_pattern']
        for field in match.keys():
            if field not in match_fields:
                self.validation_warnings.append(f"{path}.{field} 不是标准的匹配字段")

        # 验证字符串字段
        for field in ['host', 'path', 'method', 'url_pattern']:
            if field in match and not isinstance(match[field], str):
                self.validation_errors.append(f"{path}.{field} 必须是字符串")

    def _validate_pipeline_config(self, pipeline: list, path: str, config_path: str = None) -> None:
        """验证管道配置"""
        if not isinstance(pipeline, list):
            self.validation_errors.append(f"{path} 必须是数组")
            return

        for i, action in enumerate(pipeline):
            self._validate_single_action(action, f"{path}[{i}]", config_path)

    def _validate_single_action(self, action: dict, path: str, config_path: str = None) -> None:
        """验证单个动作"""
        if not isinstance(action, dict):
            self.validation_errors.append(f"{path} 必须是字典格式")
            return

        # 验证必需字段
        if 'action' not in action:
            self.validation_errors.append(f"{path} 缺少 action 字段")
            return

        action_name = action['action']

        # 验证动作类型
        valid_actions = {
            'set_header', 'remove_header', 'rewrite_url', 'set_query_param',
            'set_body_param', 'replace_body', 'replace_body_json', 'mock_response',
            'delay', 'conditional', 'short_circuit', 'set_status'
        }

        if action_name not in valid_actions:
            self.validation_errors.append(f"{path} 包含无效的动作类型: {action_name}")
            return

        # 验证动作特定参数
        if action_name == 'mock_response':
            self._validate_mock_response_action(action, path, config_path)
        elif action_name == 'delay':
            self._validate_delay_action(action, path)
        elif action_name == 'conditional':
            self._validate_conditional_action(action, path)
        elif action_name == 'replace_body_json':
            self._validate_replace_body_json_action(action, path, config_path)
        elif action_name == 'set_status':
            self._validate_set_status_action(action, path)
        elif action_name == 'remove_header':
            self._validate_remove_header_action(action, path)

    def _validate_mock_response_action(self, action: dict, path: str, config_path: str = None) -> None:
        """验证 mock_response 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # 验证必需参数 - mock_response 需要 file 或 content 之一
        if 'file' not in params and 'content' not in params:
            self.validation_errors.append(f"{path}.params 缺少 file 或 content 字段")
        elif 'file' in params:
            # 验证文件路径
            file_path = params['file']
            if config_path and not os.path.isabs(file_path):
                # 计算绝对路径
                config_dir = Path(config_path).parent
                absolute_path = (config_dir / file_path).resolve()
                if not absolute_path.exists():
                    self.validation_errors.append(f"{path}.params.file 引用的文件不存在: {absolute_path}")

        # 验证可选参数
        if 'status_code' in params:
            status_code = params['status_code']
            if not isinstance(status_code, int) or status_code < 100 or status_code > 599:
                self.validation_errors.append(f"{path}.params.status_code 必须是 100-599 之间的整数")

        if 'headers' in params:
            if not isinstance(params['headers'], dict):
                self.validation_errors.append(f"{path}.params.headers 必须是字典格式")

    def _validate_delay_action(self, action: dict, path: str) -> None:
        """验证 delay 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # 验证延迟参数
        delay_fields = ['min_ms', 'max_ms', 'mean_ms', 'std_ms']
        for field in delay_fields:
            if field in params:
                value = params[field]
                if not isinstance(value, (int, float)) or value < 0:
                    self.validation_errors.append(f"{path}.params.{field} 必须是非负数")

    def _validate_conditional_action(self, action: dict, path: str) -> None:
        """验证 conditional 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # 验证条件配置
        if 'condition' not in params:
            self.validation_errors.append(f"{path}.params 缺少 condition 字段")

        if 'true_actions' not in params:
            self.validation_errors.append(f"{path}.params 缺少 true_actions 字段")

        if 'false_actions' not in params:
            self.validation_errors.append(f"{path}.params 缺少 false_actions 字段")

    def _validate_replace_body_json_action(self, action: dict, path: str, config_path: str = None) -> None:
        """验证 replace_body_json 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # 验证必需参数
        if 'file' not in params:
            self.validation_errors.append(f"{path}.params 缺少 file 字段")
        else:
            # 验证文件路径
            file_path = params['file']
            if config_path and not os.path.isabs(file_path):
                # 计算绝对路径
                config_dir = Path(config_path).parent
                absolute_path = (config_dir / file_path).resolve()
                if not absolute_path.exists():
                    self.validation_errors.append(f"{path}.params.file 引用的文件不存在: {absolute_path}")

    def _validate_set_status_action(self, action: dict, path: str) -> None:
        """验证 set_status 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # set_status 的 params 可以是整数或字典
        if isinstance(params, int):
            # 如果是整数，直接验证状态码
            if params < 100 or params > 599:
                self.validation_errors.append(f"{path}.params 必须是 100-599 之间的整数")
        elif isinstance(params, dict):
            # 如果是字典，验证状态码字段
            if 'status_code' in params:
                status_code = params['status_code']
                if not isinstance(status_code, int) or status_code < 100 or status_code > 599:
                    self.validation_errors.append(f"{path}.params.status_code 必须是 100-599 之间的整数")
        else:
            self.validation_errors.append(f"{path}.params 必须是整数或字典")

    def _validate_remove_header_action(self, action: dict, path: str) -> None:
        """验证 remove_header 动作"""
        if 'params' not in action:
            self.validation_errors.append(f"{path} 缺少 params 字段")
            return

        params = action['params']

        # remove_header 的 params 可以是数组或字典
        if isinstance(params, list):
            # 如果是数组，检查每个元素都是字符串
            for i, header in enumerate(params):
                if not isinstance(header, str):
                    self.validation_errors.append(f"{path}.params[{i}] 必须是字符串")
        elif isinstance(params, dict):
            # 如果是字典，检查值都是字符串
            for key, value in params.items():
                if not isinstance(value, str):
                    self.validation_errors.append(f"{path}.params.{key} 必须是字符串")
        else:
            self.validation_errors.append(f"{path}.params 必须是数组或字典")

    def _validate_extends_config(self, extends: str, config_path: str = None) -> None:
        """验证继承配置"""
        if not isinstance(extends, str):
            self.validation_errors.append("extends 必须是字符串")
            return

        if config_path:
            # 验证继承文件是否存在
            config_dir = Path(config_path).parent
            extends_path = (config_dir / extends).resolve()
            if not extends_path.exists():
                self.validation_errors.append(f"继承文件不存在: {extends_path}")

    def get_default_config(self) -> dict:
        """获取默认配置"""
        return {
            'capture': {
                'enable_streaming': False,
                'enable_large_files': False,
                'large_file_threshold': 1048576,
                'save_binary_content': True,
                'binary_preview_max_bytes': 10485760,
                'enable_https': True,
                'include': {
                    'hosts': [],
                    'paths': [],
                    'methods': ['GET', 'POST']
                },
                'exclude': {
                    'hosts': [],
                    'paths': [],
                    'methods': []
                }
            },
            'rules': []
        }

    def merge_with_defaults(self, config: dict) -> dict:
        """将配置与默认值合并"""
        default_config = self.get_default_config()
        return self._deep_merge(default_config, config)

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """深度合并字典"""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result


class ConfigAnalyzer(ConfigValidator):
    """配置分析工具 - 基于 ConfigValidator 的扩展分析功能"""

    def __init__(self, config_path: str):
        super().__init__()
        self.config_path = Path(config_path).resolve()  # 转换为绝对路径
        self.original_config = self._load_config(self.config_path)
        self.resolved_config = self._resolve_all_extends()
        self.extends_chain = self._get_extends_chain()
        self.validation_result = None
        self.validate()

    def validate(self) -> Dict[str, Any]:
        """验证配置文件"""
        # 使用自定义验证逻辑，考虑规则来源
        self.validation_result = self._validate_with_rule_sources()
        return self.validation_result

    def _validate_with_rule_sources(self) -> Dict[str, Any]:
        """考虑规则来源的验证"""
        self.validation_errors = []
        self.validation_warnings = []

        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # 验证基本结构
        self._validate_basic_structure(self.resolved_config)

        # 验证 capture 配置
        if 'capture' in self.resolved_config:
            self._validate_capture_config(self.resolved_config['capture'])

        # 验证继承配置
        if 'extends' in self.original_config:
            self._validate_extends_config(self.original_config['extends'], str(self.config_path))

        # 验证规则（考虑来源）
        if 'rules' in self.resolved_config:
            self._validate_rules_with_sources()

        result['errors'] = self.validation_errors
        result['warnings'] = self.validation_warnings
        result['valid'] = len(self.validation_errors) == 0

        return result

    def _validate_rules_with_sources(self) -> None:
        """验证规则，考虑规则来源"""
        rules = self.resolved_config.get('rules', [])

        if not isinstance(rules, list):
            self.validation_errors.append("rules 必须是数组")
            return

        if len(rules) == 0:
            self.validation_warnings.append("rules 数组为空")

        # 获取规则来源信息
        rule_sources = self._get_rule_sources()

        for i, rule in enumerate(rules):
            source_file = rule_sources.get(i, str(self.config_path))
            self._validate_single_rule(rule, i, source_file)

    def is_valid(self) -> bool:
        """检查配置是否有效"""
        if self.validation_result is None:
            self.validate()
        return self.validation_result['valid']

    def get_validation_errors(self) -> List[str]:
        """获取验证错误"""
        if self.validation_result is None:
            self.validate()
        return self.validation_result['errors']

    def get_validation_warnings(self) -> List[str]:
        """获取验证警告"""
        if self.validation_result is None:
            self.validate()
        return self.validation_result['warnings']

    def _load_config(self, path: Path) -> dict:
        """加载配置文件"""
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _resolve_all_extends(self) -> dict:
        """解析所有继承关系"""
        return self._resolve_extends_recursive(self.original_config, self.config_path.parent)

    def _resolve_extends_recursive(self, config: dict, base_dir: Path) -> dict:
        """递归解析继承"""
        if 'extends' not in config:
            return config

        extends_path = (base_dir / config['extends']).resolve()  # 转换为绝对路径

        if not extends_path.exists():
            raise FileNotFoundError(f"继承文件不存在: {extends_path}")

        # 读取基础配置
        base_config = self._load_config(extends_path)
        base_config = self._resolve_extends_recursive(base_config, extends_path.parent)

        # 合并配置
        merged = base_config.copy()

        # 合并 rules
        if 'rules' in config:
            if 'rules' not in merged:
                merged['rules'] = []
            merged['rules'].extend(config['rules'])

        # 合并其他字段
        for key, value in config.items():
            if key not in ['extends', 'rules']:
                merged[key] = value

        return merged

    def _get_extends_chain(self) -> List[Dict[str, Any]]:
        """获取继承链"""
        chain = []
        current_config = self.original_config
        base_dir = self.config_path.parent

        while 'extends' in current_config:
            extends_path = (base_dir / current_config['extends']).resolve()  # 转换为绝对路径
            chain.append({
                'relative_ref': current_config['extends'],
                'absolute_path': str(extends_path),
                'exists': extends_path.exists(),
                'parent_dir': str(base_dir.resolve())
            })

            if extends_path.exists():
                current_config = self._load_config(extends_path)
                base_dir = extends_path.parent
            else:
                break

        return chain

    def get_extends_files_content(self) -> Dict[str, dict]:
        """获取所有继承文件的内容"""
        content = {}

        for item in self.extends_chain:
            if item['exists']:
                content[item['absolute_path']] = self._load_config(Path(item['absolute_path']))

        return content

    def analyze_rules(self) -> Dict[str, Any]:
        """分析规则"""
        rules = self.resolved_config.get('rules', [])

        analysis = {
            'total_rules': len(rules),
            'enabled_rules': len([r for r in rules if r.get('enabled', True)]),
            'rules_by_action': {},
            'file_dependencies': set(),
            'file_dependencies_absolute': set(),  # 绝对路径的文件依赖
            'rules_detail': []
        }

        # 获取规则来源信息
        rule_sources = self._get_rule_sources()

        for i, rule in enumerate(rules):
            rule_detail = {
                'index': i,
                'name': rule.get('name', f'Rule {i + 1}'),
                'enabled': rule.get('enabled', True),
                'match_conditions': rule.get('match', {}),
                'actions': [],
                'file_dependencies': [],
                'source_file': rule_sources.get(i, str(self.config_path))
            }

            # 分析请求和响应管道
            for pipeline in ['request_pipeline', 'response_pipeline']:
                for action in rule.get(pipeline, []):
                    action_name = action.get('action', 'unknown')
                    action_detail = {
                        'pipeline': pipeline,
                        'action': action_name,
                        'params': action.get('params', {})
                    }
                    rule_detail['actions'].append(action_detail)

                    # 统计动作类型
                    analysis['rules_by_action'][action_name] = analysis['rules_by_action'].get(action_name, 0) + 1

                    # 收集文件依赖
                    if action_name == 'mock_response' and 'file' in action.get('params', {}):
                        file_path = action['params']['file']
                        analysis['file_dependencies'].add(file_path)

                        # 转换为绝对路径，考虑规则来源
                        absolute_file_path = self._resolve_file_path(file_path,
                                                                     rule_sources.get(i, str(self.config_path)))

                        analysis['file_dependencies_absolute'].add(str(absolute_file_path))
                        rule_detail['file_dependencies'].append({
                            'relative_path': file_path,
                            'absolute_path': str(absolute_file_path),
                            'exists': absolute_file_path.exists(),
                            'source_file': rule_sources.get(i, str(self.config_path))
                        })

            analysis['rules_detail'].append(rule_detail)

        # 转换 set 为 list
        analysis['file_dependencies'] = list(analysis['file_dependencies'])
        analysis['file_dependencies_absolute'] = list(analysis['file_dependencies_absolute'])

        return analysis

    def get_file_dependencies_status(self) -> Dict[str, Dict[str, Any]]:
        """获取文件依赖状态"""
        dependencies = {}

        for file_path in self.analyze_rules()['file_dependencies_absolute']:
            path_obj = Path(file_path)

            # 安全地计算相对路径
            relative_to_config = self._calculate_relative_path(path_obj, self.config_path.parent)

            dependencies[file_path] = {
                'exists': path_obj.exists(),
                'is_file': path_obj.is_file() if path_obj.exists() else False,
                'size': path_obj.stat().st_size if path_obj.exists() and path_obj.is_file() else 0,
                'parent_dir': str(path_obj.parent),
                'relative_to_config': relative_to_config
            }

        return dependencies

    def _calculate_relative_path(self, target_path: Path, base_path: Path) -> Optional[str]:
        """安全地计算相对路径"""
        if not target_path.exists():
            return None

        try:
            # 尝试计算相对于基础路径的相对路径
            return str(target_path.relative_to(base_path))
        except ValueError:
            # 如果不在子目录中，尝试找到共同的父目录
            try:
                # 获取两个路径的共同部分
                target_parts = target_path.parts
                base_parts = base_path.parts

                # 找到共同的前缀
                common_parts = []
                for i, (target_part, base_part) in enumerate(zip(target_parts, base_parts)):
                    if target_part == base_part:
                        common_parts.append(target_part)
                    else:
                        break

                if common_parts:
                    # 计算从共同目录到目标文件的相对路径
                    common_path = Path(*common_parts)
                    return str(target_path.relative_to(common_path))
                else:
                    # 没有共同路径，返回绝对路径
                    return str(target_path)

            except (ValueError, IndexError):
                # 如果还是失败，返回绝对路径
                return str(target_path)

    def _get_rule_sources(self) -> Dict[int, str]:
        """获取每个规则的来源文件"""
        rule_sources = {}
        rule_index = 0

        # 首先处理继承文件中的规则
        for item in self.extends_chain:
            if item['exists']:
                extends_content = self._load_config(Path(item['absolute_path']))
                extends_rules = extends_content.get('rules', [])

                for _ in extends_rules:
                    rule_sources[rule_index] = item['absolute_path']
                    rule_index += 1

        # 然后处理当前文件中的规则
        current_rules = self.original_config.get('rules', [])
        for _ in current_rules:
            rule_sources[rule_index] = str(self.config_path)
            rule_index += 1

        return rule_sources

    def _resolve_file_path(self, file_path: str, source_file: str) -> Path:
        """根据规则来源文件解析文件路径"""
        if os.path.isabs(file_path):
            return Path(file_path).resolve()

        # 相对于规则来源文件的目录
        source_dir = Path(source_file).parent
        return (source_dir / file_path).resolve()

    def generate_report(self, output_format: str = 'text') -> str:
        """生成分析报告"""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """生成文本格式报告"""
        report = []
        report.append("=" * 80)
        report.append("UProxier 配置分析报告")
        report.append("=" * 80)
        report.append(f"配置文件: {self.config_path}")
        report.append(f"配置文件目录: {self.config_path.parent}")
        report.append("")

        # 配置验证结果
        report.append("配置验证:")
        report.append("-" * 40)
        if self.is_valid():
            report.append("✅ 配置有效")
        else:
            report.append("❌ 配置无效")

        errors = self.get_validation_errors()
        warnings = self.get_validation_warnings()

        if errors:
            report.append(f"错误 ({len(errors)} 个):")
            for error in errors:
                report.append(f"  ❌ {error}")

        if warnings:
            report.append(f"警告 ({len(warnings)} 个):")
            for warning in warnings:
                report.append(f"  ⚠️  {warning}")

        report.append("")

        # 继承链信息
        report.append("继承链:")
        report.append("-" * 40)
        for i, item in enumerate(self.extends_chain):
            report.append(f"  {i + 1}. 相对引用: {item['relative_ref']}")
            report.append(f"     绝对路径: {item['absolute_path']}")
            report.append(f"     父目录: {item['parent_dir']}")
            report.append(f"     存在: {'是' if item['exists'] else '否'}")
            report.append("")

        # 规则分析
        analysis = self.analyze_rules()
        report.append("规则分析:")
        report.append("-" * 40)
        report.append(f"总规则数: {analysis['total_rules']}")
        report.append(f"启用规则数: {analysis['enabled_rules']}")
        report.append("")

        report.append("动作类型统计:")
        for action, count in analysis['rules_by_action'].items():
            report.append(f"  {action}: {count} 次")
        report.append("")

        # 文件依赖
        report.append("文件依赖:")
        report.append("-" * 40)
        dependencies = self.get_file_dependencies_status()
        for file_path, status in dependencies.items():
            report.append(f"文件: {file_path}")
            report.append(f"  存在: {'是' if status['exists'] else '否'}")
            if status['exists']:
                report.append(f"  大小: {status['size']} 字节")
                report.append(f"  父目录: {status['parent_dir']}")
                if status['relative_to_config']:
                    report.append(f"  相对于配置: {status['relative_to_config']}")
            report.append("")

        # 详细规则信息
        report.append("详细规则信息:")
        report.append("-" * 40)
        for rule_detail in analysis['rules_detail']:
            report.append(f"规则 {rule_detail['index'] + 1}: {rule_detail['name']}")
            report.append(f"  启用: {'是' if rule_detail['enabled'] else '否'}")
            report.append(f"  规则来源: {rule_detail['source_file']}")
            report.append(f"  匹配条件: {rule_detail['match_conditions']}")
            report.append(f"  动作数: {len(rule_detail['actions'])}")

            if rule_detail['file_dependencies']:
                report.append("  文件依赖:")
                for dep in rule_detail['file_dependencies']:
                    report.append(f"    相对路径: {dep['relative_path']}")
                    report.append(f"    绝对路径: {dep['absolute_path']}")
                    report.append(f"    存在: {'是' if dep['exists'] else '否'}")
            report.append("")

        return "\n".join(report)

    def _generate_json_report(self) -> str:
        """生成JSON格式报告"""
        analysis = self.analyze_rules()
        dependencies = self.get_file_dependencies_status()

        report = {
            'config_file': {
                'path': str(self.config_path),
                'parent_dir': str(self.config_path.parent)
            },
            'validation': {
                'valid': self.is_valid(),
                'errors': self.get_validation_errors(),
                'warnings': self.get_validation_warnings()
            },
            'extends_chain': self.extends_chain,
            'rules_analysis': analysis,
            'file_dependencies': dependencies,
            'extends_files_content': self.get_extends_files_content()
        }

        return json.dumps(report, indent=2, ensure_ascii=False)
