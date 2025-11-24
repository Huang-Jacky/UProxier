#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP 相关工具函数
"""

from typing import Any, Mapping


def get_header_value(headers: Mapping[str, Any], header_name: str) -> str:
    """
    大小写不敏感地获取 header 值

    Args:
        headers: header 字典
        header_name: 目标 header 名称

    Returns:
        str: header 值（若不存在则返回空字符串）
    """
    if not headers or not header_name:
        return ''

    target = header_name.lower()
    try:
        for key, value in headers.items():
            if str(key).lower() == target:
                return value
    except Exception:
        pass

    try:
        return (
            headers.get(header_name)
            or headers.get(header_name.lower())
            or headers.get(header_name.upper())
            or ''
        )
    except Exception:
        return ''

