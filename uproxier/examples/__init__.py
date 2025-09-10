#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UProxier 规则示例模块

提供各种规则配置示例，包括基础 action、匹配条件、复杂工作流等。
"""

from pathlib import Path

# 获取示例文件目录
EXAMPLES_DIR = Path(__file__).parent


def get_example_files():
    """获取所有示例 YAML 文件"""
    yaml_files = []
    for file_path in EXAMPLES_DIR.glob("*.yaml"):
        if file_path.name != "README.md":
            yaml_files.append(file_path)
    return sorted(yaml_files)


def get_example_content(filename):
    """获取指定示例文件的内容"""
    file_path = EXAMPLES_DIR / filename
    if file_path.exists():
        return file_path.read_text(encoding='utf-8')
    return None


def get_readme_content():
    """获取示例 README 内容"""
    readme_path = EXAMPLES_DIR / "README.md"
    if readme_path.exists():
        return readme_path.read_text(encoding='utf-8')
    return None


def list_examples():
    """列出所有可用的示例文件"""
    examples = []
    for file_path in get_example_files():
        examples.append({
            'filename': file_path.name,
            'name': file_path.stem,
            'description': _get_example_description(file_path)
        })
    return examples


def _get_example_description(file_path):
    """从文件内容中提取描述"""
    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.split('\n')
        for line in lines[:10]:  # 只检查前10行
            if line.startswith('# ') and not line.startswith('# ' + file_path.stem):
                return line[2:].strip()
    except Exception:
        pass
    return file_path.stem.replace('_', ' ').title()
