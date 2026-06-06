import re
import time
import ssl
import urllib.request
import urllib.error
from typing import Optional, Dict, List, Callable, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs


@dataclass
class Vulnerability:
    name: str
    vuln_type: str
    severity: str
    location: str
    description: str
    remediation: str
    owasp_category: str
    evidence: str = ""


@dataclass
class ActiveScanReport:
    url: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: float = 0.0
    risk_level: str = "低"
    cnt: int = 0


# 临时payload字典，不硬编码在类里
_PAYLOADS = {
    'xss': [
        "<script>alert('XSS')</script>",
        # "<img src=x onerror=alert('XSS')>",  # 注释掉一个
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(1)'>",  # 新增一个
    ],
    'sqli': [
        "' OR '1'='1",
        "' OR '1'='1'--",
        # "' UNION SELECT NULL--",  # 注释掉
        "1' AND '1'='1",
        "' UNION SELECT 1,2,3--",  # 新增
    ],
    'cmd': [
        "| ls",
        "; ls",
        # "& whoami",  # 注释掉
        "`whoami`",
        "$(id)",  # 新增
    ],
    'path': [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",  # 新增
    ]
}

_OWASP_MAP = {
    'xss': 'A03:2021',
    'sqli': 'A03:2021',
    'command_injection': 'A03:2021',
    'path_traversal': 'A01:2021',
}


class ActiveScanner:

    def __init__(self):
        self._stop_flag = False
        self.timeout = 10

    def stop_scan(self):
        self._stop_flag = True

    def scan_url(self, url: str, parameters: Dict[str, str] = None,
                 scan_types: List[str] = None,
                 progress_callback: Callable = None,
                 html_content: str = None) -> ActiveScanReport:
        self._stop_flag = False
        start_time = time.time()
        vulnerabilities = []
        cnt = 0

        parsed = urlparse(url)

        if scan_types is None:
            scan_types = ['xss', 'sqli', 'command_injection', 'path_traversal']

        params = dict(parse_qs(parsed.query))
        # 无参时尝试从页面表单提取参数，不自动硬补q/id
        if not params and html_content:
            params = self._extract_form_params(html_content)
            if progress_callback and params:
                progress_callback(f"从页面提取到 {len(params)} 个表单参数", 5)

        if not params:
            if progress_callback:
                progress_callback("无URL参数且页面无可扫描参数，跳过参数扫描", 100)
            return ActiveScanReport(
                url=url, vulnerabilities=[],
                scan_time=time.time()-start_time, risk_level="低",
                cnt=0
            )

        total_scans = len(scan_types)
        for i, scan_type in enumerate(scan_types):
            if self._stop_flag:
                break

            progress = int((i / total_scans) * 80) + 10
            if progress_callback:
                progress_callback(f"正在扫描: {scan_type.upper()}", progress)

            if scan_type == 'xss':
                vulns, c = self._scan_xss(url, params)
                vulnerabilities.extend(vulns)
                cnt += c
            elif scan_type == 'sqli':
                vulns, c = self._scan_sqli(url, params)
                vulnerabilities.extend(vulns)
                cnt += c
            elif scan_type == 'command_injection':
                vulns, c = self._scan_command_injection(url, params)
                vulnerabilities.extend(vulns)
                cnt += c
            elif scan_type == 'path_traversal':
                vulns, c = self._scan_path_traversal(url, params)
                vulnerabilities.extend(vulns)
                cnt += c

        risk_level = self._calc_risk(vulnerabilities)
        scan_time = time.time() - start_time

        if progress_callback:
            progress_callback("扫描完成", 100)

        return ActiveScanReport(
            url=url, vulnerabilities=vulnerabilities,
            scan_time=scan_time, risk_level=risk_level,
            cnt=cnt
        )

    def _extract_form_params(self, html: str) -> Dict[str, List[str]]:
        """从HTML表单中提取可扫描参数"""
        params = {}
        # 提取input name
        for m in re.finditer(r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?', html, re.IGNORECASE):
            params[m.group(1)] = ['test']
        # 提取select name
        for m in re.finditer(r'<select[^>]*name=["\']?([^"\'>\s]+)["\']?', html, re.IGNORECASE):
            params[m.group(1)] = ['test']
        # 提取textarea name
        for m in re.finditer(r'<textarea[^>]*name=["\']?([^"\'>\s]+)["\']?', html, re.IGNORECASE):
            params[m.group(1)] = ['test']
        return params

    def _scan_xss(self, url: str, params: Dict[str, List[str]]) -> Tuple[List[Vulnerability], int]:
        vulns = []
        c = 0

        for param_name in params.keys():
            for payload in _PAYLOADS['xss']:
                if self._stop_flag:
                    break
                test_url = self._build_test_url(url, param_name, payload)
                try:
                    response = self._make_request(test_url)
                    c += 1
                    if response and payload in response:
                        vulns.append(Vulnerability(
                            name="跨站脚本攻击(XSS)", vuln_type="xss", severity="高危",
                            location=f"参数: {param_name}",
                            description=f"在参数 '{param_name}' 中发现反射型XSS漏洞",
                            remediation="对用户输入进行严格的过滤和编码，启用CSP头",
                            owasp_category=_OWASP_MAP['xss'], evidence=payload))
                        break
                except urllib.error.URLError as e:
                    print(f"[WARN] XSS扫描请求失败: {e}")
                except ValueError as e:
                    print(f"[WARN] XSS扫描解码失败: {e}")
        return vulns, c

    def _scan_sqli(self, url: str, params: Dict[str, List[str]]) -> Tuple[List[Vulnerability], int]:
        vulns = []
        c = 0
        sql_err = [
            r"SQL syntax.*MySQL", r"PostgreSQL.*ERROR", r"ORA-\d{5}",
            r"Microsoft SQL Server", r"Incorrect syntax",
            r"mysql_fetch", r"mysql_num_rows", r"sqlite3.OperationalError"
        ]

        for param_name in params.keys():
            for payload in _PAYLOADS['sqli']:
                if self._stop_flag:
                    break
                test_url = self._build_test_url(url, param_name, payload)
                try:
                    response = self._make_request(test_url)
                    c += 1
                    if response:
                        for pattern in sql_err:
                            if re.search(pattern, response, re.IGNORECASE):
                                vulns.append(Vulnerability(
                                    name="SQL注入漏洞", vuln_type="sqli", severity="严重",
                                    location=f"参数: {param_name}",
                                    description=f"在参数 '{param_name}' 中发现SQL注入漏洞",
                                    remediation="使用参数化查询或预编译语句，实施最小权限原则",
                                    owasp_category=_OWASP_MAP['sqli'], evidence=pattern))
                                break
                except urllib.error.URLError as e:
                    print(f"[WARN] SQLi扫描请求失败: {e}")
                except ValueError as e:
                    print(f"[WARN] SQLi扫描解码失败: {e}")
        return vulns, c

    def _scan_command_injection(self, url: str, params: Dict[str, List[str]]) -> Tuple[List[Vulnerability], int]:
        vulns = []
        c = 0

        for param_name in params.keys():
            for payload in _PAYLOADS['cmd']:
                if self._stop_flag:
                    break
                test_url = self._build_test_url(url, param_name, payload)
                try:
                    response = self._make_request(test_url)
                    c += 1
                    cmd_indicators = ['root:x:', '/bin/bash', '/bin/sh', 'Windows']
                    for indicator in cmd_indicators:
                        if response and indicator in response:
                            vulns.append(Vulnerability(
                                name="命令注入漏洞", vuln_type="command_injection", severity="严重",
                                location=f"参数: {param_name}",
                                description=f"在参数 '{param_name}' 中发现命令注入漏洞",
                                remediation="禁用系统命令执行函数，过滤特殊字符",
                                owasp_category=_OWASP_MAP['command_injection'], evidence=payload))
                            break
                except urllib.error.URLError as e:
                    print(f"[WARN] 命令注入扫描请求失败: {e}")
                except ValueError as e:
                    print(f"[WARN] 命令注入扫描解码失败: {e}")
        return vulns, c

    def _scan_path_traversal(self, url: str, params: Dict[str, List[str]]) -> Tuple[List[Vulnerability], int]:
        vulns = []
        c = 0

        for param_name in params.keys():
            for payload in _PAYLOADS['path']:
                if self._stop_flag:
                    break
                test_url = self._build_test_url(url, param_name, payload)
                try:
                    response = self._make_request(test_url)
                    c += 1
                    sensitive = [r'root:.*:0:0:', r'\[boot loader\]', r'Windows\\']
                    for pattern in sensitive:
                        if response and re.search(pattern, response):
                            vulns.append(Vulnerability(
                                name="路径遍历漏洞", vuln_type="path_traversal", severity="高危",
                                location=f"参数: {param_name}",
                                description=f"在参数 '{param_name}' 中发现路径遍历漏洞",
                                remediation="过滤路径遍历字符，使用安全的文件路径解析API",
                                owasp_category=_OWASP_MAP['path_traversal'], evidence=payload))
                            break
                except urllib.error.URLError as e:
                    print(f"[WARN] 路径遍历扫描请求失败: {e}")
                except ValueError as e:
                    print(f"[WARN] 路径遍历扫描解码失败: {e}")
        return vulns, c

    def _build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param_name] = [payload]
        new_query = urlencode(query_params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _make_request(self, url: str) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            request = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            })

            with urllib.request.urlopen(request, timeout=self.timeout, context=ctx) as response:
                return response.read().decode('utf-8', errors='ignore')

        except urllib.error.URLError as e:
            print(f"[WARN] URL请求失败: {e}")
            return None
        except urllib.error.HTTPError as e:
            print(f"[WARN] HTTP错误: {e.code}")
            return None
        except ssl.SSLError as e:
            print(f"[WARN] SSL错误: {e}")
            return None
        except ValueError as e:
            print(f"[WARN] 解码失败: {e}")
            return None

    def _calc_risk(self, vulnerabilities: List[Vulnerability]) -> str:
        if not vulnerabilities:
            return "低"
        for vuln in vulnerabilities:
            if vuln.severity == "严重":
                return "严重"
        for vuln in vulnerabilities:
            if vuln.severity == "高危":
                return "高"
        return "中"
