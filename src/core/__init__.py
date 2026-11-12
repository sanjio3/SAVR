"""
Core module
"""
from .config import config
from .scanner import FileScanner
from .models import (
    Vulnerability,
    ScanResult,
    BenchmarkResult,
    Severity,
    VulnerabilityType
)

# 新增模块
from .poc_generator import POCGenerator
from .endpoint_discoverer import EndpointDiscoverer, extract_endpoints_from_files
from .vuln_processor import (
    VulnerabilityMerger,
    FalsePositiveFilter,
    ResultGrouper,
    process_vulnerabilities
)

__all__ = [
    'config',
    'FileScanner',
    'Vulnerability',
    'ScanResult',
    'BenchmarkResult',
    'Severity',
    'VulnerabilityType',
    'POCGenerator',
    'EndpointDiscoverer',
    'extract_endpoints_from_files',
    'VulnerabilityMerger',
    'FalsePositiveFilter',
    'ResultGrouper',
    'process_vulnerabilities'
]
