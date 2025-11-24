#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络工具函数
"""

import socket
from typing import Optional


def get_local_ip() -> Optional[str]:
    """
    获取本机局域网 IP 地址

    Returns:
        Optional[str]: 成功返回 IP，失败返回 None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def get_display_host(bind_host: str, default: str = "127.0.0.1") -> str:
    """
    获取用于显示的主机地址
    """
    if bind_host in ("0.0.0.0", "::"):
        local_ip = get_local_ip()
        return local_ip or default

    return bind_host

