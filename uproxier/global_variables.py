#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
全局变量存储系统
支持跨请求的数据共享和模板变量替换
"""

import threading
import time
from typing import Dict, Any, Optional
from datetime import datetime


class GlobalVariableManager:
    """全局变量管理器 - 单例模式"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self._variables: Dict[str, Any] = {}
            self._variable_locks: Dict[str, threading.RLock] = {}
            self._initialized = True
    
    def set_variable(self, name: str, value: Any) -> None:
        """设置全局变量
        
        Args:
            name: 变量名
            value: 变量值
        """
        with self._lock:
            self._variables[name] = value
            if name not in self._variable_locks:
                self._variable_locks[name] = threading.RLock()
    
    def get_variable(self, name: str) -> Any:
        """获取全局变量
        
        Args:
            name: 变量名
            
        Returns:
            变量值，如果不存在返回 None
        """
        with self._lock:
            return self._variables.get(name)
    
    def delete_variable(self, name: str) -> bool:
        """删除全局变量
        
        Args:
            name: 变量名
            
        Returns:
            是否成功删除
        """
        with self._lock:
            if name in self._variables:
                del self._variables[name]
                return True
            return False
    
    def clear_all(self) -> None:
        with self._lock:
            self._variables.clear()
    
    def list_variables(self) -> Dict[str, Any]:
        with self._lock:
            return self._variables.copy()
    


global_vars = GlobalVariableManager()


def process_template_variables(text: str) -> str:
    """处理模板变量替换
    
    Args:
        text: 包含模板变量的文本
        
    Returns:
        替换后的文本
    """
    if not isinstance(text, str):
        return text
    
    # 处理 {{variable}} 格式的变量
    import re
    
    def replace_variable(match):
        var_name = match.group(1).strip()
        
        # 内置变量
        if var_name == 'timestamp':
            return str(int(time.time()))
        elif var_name == 'datetime':
            return datetime.now().isoformat()
        elif var_name == 'random':
            import random
            return str(random.randint(1000, 9999))
        
        # 处理 data.field 格式
        if var_name.startswith('data.'):
            # 这里需要从响应数据中提取，暂时返回原文本
            # 实际实现需要在处理器中处理
            return match.group(0)
        
        # 全局变量
        value = global_vars.get_variable(var_name)
        if value is not None:
            return str(value)
        
        # 如果变量不存在，返回原文本
        return match.group(0)
    
    # 匹配 {{variable}} 格式
    pattern = r'\{\{\s*([^}]+)\s*\}\}'
    return re.sub(pattern, replace_variable, text)


def process_template_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """递归处理字典中的模板变量
    
    Args:
        data: 包含模板变量的字典
        
    Returns:
        处理后的字典
    """
    if not isinstance(data, dict):
        return data
    
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = process_template_variables(value)
        elif isinstance(value, dict):
            result[key] = process_template_dict(value)
        elif isinstance(value, list):
            result[key] = [process_template_variables(item) if isinstance(item, str) else item for item in value]
        else:
            result[key] = value
    
    return result
