#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UProxier 异常处理模块

定义统一的异常体系，提供更好的错误处理和调试信息。
"""

from typing import Optional, Dict, Any, List


class UProxierError(Exception):
    """UProxier 基础异常类
    
    所有 UProxier 相关异常的基类，提供统一的错误处理接口。
    """
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        """初始化异常
        
        Args:
            message: 错误消息
            error_code: 错误代码，用于程序化处理
            details: 额外的错误详情
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
    
    def __str__(self) -> str:
        """返回格式化的错误信息"""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message
    
    def to_dict(self) -> Dict[str, Any]:
        """将异常转换为字典格式，便于序列化"""
        return {
            'error_type': self.__class__.__name__,
            'error_code': self.error_code,
            'message': self.message,
            'details': self.details
        }


class ConfigError(UProxierError):
    """配置相关错误"""
    pass


class ConfigValidationError(ConfigError):
    """配置验证错误"""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Optional[Any] = None, suggestions: Optional[List[str]] = None):
        """初始化配置验证错误
        
        Args:
            message: 错误消息
            field: 出错的配置字段
            value: 错误的值
            suggestions: 修复建议
        """
        details = {}
        if field:
            details['field'] = field
        if value is not None:
            details['value'] = value
        if suggestions:
            details['suggestions'] = suggestions
            
        super().__init__(message, 'CONFIG_VALIDATION_ERROR', details)
        self.field = field
        self.value = value
        self.suggestions = suggestions or []


class ConfigInheritanceError(ConfigError):
    """配置继承错误"""
    
    def __init__(self, message: str, extends_file: Optional[str] = None,
                 current_file: Optional[str] = None, resolved_path: Optional[str] = None,
                 suggestions: Optional[List[str]] = None):
        """初始化配置继承错误
        
        Args:
            message: 错误消息
            extends_file: 继承的配置文件路径
            current_file: 当前配置文件路径
            resolved_path: 解析后的路径
            suggestions: 修复建议
        """
        details = {}
        if extends_file:
            details['extends_file'] = extends_file
        if current_file:
            details['current_file'] = current_file
        if resolved_path:
            details['resolved_path'] = resolved_path
        if suggestions:
            details['suggestions'] = suggestions
            
        super().__init__(message, 'CONFIG_INHERITANCE_ERROR', details)
        self.extends_file = extends_file
        self.current_file = current_file
        self.resolved_path = resolved_path
        self.suggestions = suggestions or []


class RuleError(UProxierError):
    """规则相关错误"""
    pass


class RuleValidationError(RuleError):
    """规则验证错误"""
    
    def __init__(self, message: str, rule_name: Optional[str] = None,
                 rule_index: Optional[int] = None, field: Optional[str] = None,
                 suggestions: Optional[List[str]] = None):
        """初始化规则验证错误
        
        Args:
            message: 错误消息
            rule_name: 规则名称
            rule_index: 规则索引
            field: 出错的字段
            suggestions: 修复建议
        """
        details = {}
        if rule_name:
            details['rule_name'] = rule_name
        if rule_index is not None:
            details['rule_index'] = rule_index
        if field:
            details['field'] = field
        if suggestions:
            details['suggestions'] = suggestions
            
        super().__init__(message, 'RULE_VALIDATION_ERROR', details)
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.field = field
        self.suggestions = suggestions or []


class RuleExecutionError(RuleError):
    """规则执行错误"""
    
    def __init__(self, message: str, rule_name: Optional[str] = None,
                 action: Optional[str] = None, request_id: Optional[str] = None):
        """初始化规则执行错误
        
        Args:
            message: 错误消息
            rule_name: 规则名称
            action: 执行的动作
            request_id: 请求ID
        """
        details = {}
        if rule_name:
            details['rule_name'] = rule_name
        if action:
            details['action'] = action
        if request_id:
            details['request_id'] = request_id
            
        super().__init__(message, 'RULE_EXECUTION_ERROR', details)
        self.rule_name = rule_name
        self.action = action
        self.request_id = request_id


class CertificateError(UProxierError):
    """证书相关错误"""
    pass


class CertificateGenerationError(CertificateError):
    """证书生成错误"""
    
    def __init__(self, message: str, cert_path: Optional[str] = None):
        """初始化证书生成错误
        
        Args:
            message: 错误消息
            cert_path: 证书路径
        """
        details = {}
        if cert_path:
            details['cert_path'] = cert_path
            
        super().__init__(message, 'CERT_GENERATION_ERROR', details)
        self.cert_path = cert_path


class CertificateValidationError(CertificateError):
    """证书验证错误"""
    
    def __init__(self, message: str, cert_path: Optional[str] = None,
                 validation_type: Optional[str] = None):
        """初始化证书验证错误
        
        Args:
            message: 错误消息
            cert_path: 证书路径
            validation_type: 验证类型
        """
        details = {}
        if cert_path:
            details['cert_path'] = cert_path
        if validation_type:
            details['validation_type'] = validation_type
            
        super().__init__(message, 'CERT_VALIDATION_ERROR', details)
        self.cert_path = cert_path
        self.validation_type = validation_type


class ProxyError(UProxierError):
    """代理相关错误"""
    pass


class ProxyStartupError(ProxyError):
    """代理启动错误"""
    
    def __init__(self, message: str, port: Optional[int] = None,
                 web_port: Optional[int] = None):
        """初始化代理启动错误
        
        Args:
            message: 错误消息
            port: 代理端口
            web_port: Web界面端口
        """
        details = {}
        if port:
            details['port'] = port
        if web_port:
            details['web_port'] = web_port
            
        super().__init__(message, 'PROXY_STARTUP_ERROR', details)
        self.port = port
        self.web_port = web_port


class WebInterfaceError(UProxierError):
    """Web界面相关错误"""
    pass


class WebInterfaceStartupError(WebInterfaceError):
    """Web界面启动错误"""
    
    def __init__(self, message: str, port: Optional[int] = None):
        """初始化Web界面启动错误
        
        Args:
            message: 错误消息
            port: Web界面端口
        """
        details = {}
        if port:
            details['port'] = port
            
        super().__init__(message, 'WEB_INTERFACE_STARTUP_ERROR', details)
        self.port = port


class FileOperationError(UProxierError):
    """文件操作相关错误"""
    pass


class FileNotFoundError(FileOperationError):
    """文件未找到错误"""
    
    def __init__(self, message: str, file_path: Optional[str] = None,
                 suggestions: Optional[List[str]] = None):
        """初始化文件未找到错误
        
        Args:
            message: 错误消息
            file_path: 文件路径
            suggestions: 修复建议
        """
        details = {}
        if file_path:
            details['file_path'] = file_path
        if suggestions:
            details['suggestions'] = suggestions
            
        super().__init__(message, 'FILE_NOT_FOUND_ERROR', details)
        self.file_path = file_path
        self.suggestions = suggestions or []


class FilePermissionError(FileOperationError):
    """文件权限错误"""
    
    def __init__(self, message: str, file_path: Optional[str] = None,
                 operation: Optional[str] = None):
        """初始化文件权限错误
        
        Args:
            message: 错误消息
            file_path: 文件路径
            operation: 操作类型
        """
        details = {}
        if file_path:
            details['file_path'] = file_path
        if operation:
            details['operation'] = operation
            
        super().__init__(message, 'FILE_PERMISSION_ERROR', details)
        self.file_path = file_path
        self.operation = operation


# 向后兼容的异常别名
UProxierFileNotFoundError = FileNotFoundError
UProxierConfigError = ConfigError
UProxierRuleError = RuleError
