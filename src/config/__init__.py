"""
配置模块
统一管理所有配置
"""
from .loader import ConfigLoader, get_config

__all__ = ['ConfigLoader', 'get_config']
