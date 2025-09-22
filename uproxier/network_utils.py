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
        str: 本机 IP 地址，如果获取失败返回 None
    """
    try:
        # 创建一个 UDP socket 连接到外部地址
        # 这样不会实际发送数据，只是获取本机 IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def get_display_host(bind_host: str, default: str = "127.0.0.1") -> str:
    """
    获取用于显示的 IP 地址
    
    Args:
        bind_host: 绑定的主机地址
        default: 默认返回地址
        
    Returns:
        str: 用于显示的 IP 地址
    """
    # 如果绑定的是 0.0.0.0 或 ::，获取本机 IP
    if bind_host in ("0.0.0.0", "::"):
        local_ip = get_local_ip()
        return local_ip or default
    
    return bind_host
