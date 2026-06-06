# -*- coding: utf-8 -*-
"""
 静态分析器
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .url_parser import URLInfo, FormInfo, ScriptInfo


@dataclass
class PassiveAnalysisReport:
    url: str
    url_info: URLInfo
    forms: List[FormInfo] = field(default_factory=list)
    scripts: List[ScriptInfo] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    risk_level: str = "安全"
    risk_score: int = 0
    vulnerabilities: List[Dict] = field(default_factory=list)


class PassiveAnalyzer:


    def __init__(self):
        pass

    def analyze(self, url: str, html: str) -> PassiveAnalysisReport:



        url_info = self._parse_url(url)

        forms = self._parse_forms(html)
        scripts = self._parse_scripts(html)
        security_headers = {}

        vulnerabilities = []
        issues = []


        if not url_info.is_https:
            issues.append("中危: 连接未使用HTTPS，数据传输可能被窃听")


        stored_xss = self._detect_stored_xss(html)
        if stored_xss:
            vulnerabilities.append(stored_xss)
            issues.append(f"高危: 存储型XSS - {stored_xss['location']}")


        dom_xss = self._detect_dom_xss(html)
        if dom_xss:
            vulnerabilities.append(dom_xss)
            issues.append(f"高危: DOM型XSS - {dom_xss['location']}")


        reflected_xss = self._detect_reflected_xss(url)
        if reflected_xss:
            vulnerabilities.append(reflected_xss)
            issues.append(f"高危: 反射型XSS - {reflected_xss['location']}")


        csrf = self._detect_csrf(forms)
        if csrf:
            vulnerabilities.append(csrf)
            issues.append(f"中危: CSRF - {csrf['location']}")


        cookie_issues = self._detect_cookie_issues(html)
        for issue in cookie_issues:
            vulnerabilities.append(issue)
            issues.append(f"低危: Cookie安全 - {issue['location']}")


        info_leak = self._detect_info_leak(html)
        if info_leak:
            vulnerabilities.append(info_leak)
            issues.append(f"低危: 信息泄露 - {info_leak['location']}")


        js_risks = self._detect_js_risks(scripts)
        for risk in js_risks:
            issues.append(risk)


        risk_score = self._calc_risk_score(vulnerabilities, issues)
        risk_level = self._get_risk_level(risk_score)

        return PassiveAnalysisReport(
            url=url,
            url_info=url_info,
            forms=forms,
            scripts=scripts,
            security_headers=security_headers,
            issues=issues,
            risk_level=risk_level,
            risk_score=risk_score,
            vulnerabilities=vulnerabilities
        )

    def _parse_url(self, url: str) -> URLInfo:

        try:
            parsed = urlparse(url)
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc))
            return URLInfo(
                url=url,
                protocol=parsed.scheme,
                domain=parsed.netloc,
                path=parsed.path,
                query_params={},
                is_https=parsed.scheme == 'https',
                is_ip=is_ip,
                suspicious_params=[]
            )
        except:
            return URLInfo(url=url)

    def _parse_forms(self, html: str) -> List[FormInfo]:
        """解析表单"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            form_info = FormInfo()

            action_match = re.search(r'action=["\']?([^"\'>\s]*)["\']?', form_html, re.IGNORECASE)
            if action_match:
                form_info.action = action_match.group(1)

            method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE)
            if method_match:
                form_info.method = method_match.group(1).upper()

            if 'type="password"' in form_html or "type='password'" in form_html:
                form_info.has_password = True

            form_info.uses_https = form_info.action.startswith('https://') if form_info.action else True
            forms.append(form_info)

        return forms

    def _parse_scripts(self, html: str) -> List[ScriptInfo]:

        scripts = []
        script_pattern = r'<script[^>]*>(.*?)</script>'

        for match in re.finditer(script_pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1)
            script_info = ScriptInfo(content=content)

            src_match = re.search(r'src=["\']?([^"\'>\s]+)["\']?', match.group(0), re.IGNORECASE)
            if src_match:
                script_info.src = src_match.group(1)
                script_info.is_external = True

            if content:
                script_info.uses_eval = 'eval(' in content
                script_info.uses_innerhtml = '.innerHTML' in content
                script_info.uses_document_write = 'document.write' in content

            scripts.append(script_info)

        return scripts

    def _detect_stored_xss(self, html: str) -> Optional[Dict]:

        user_sources = [
            r'location\.\w+',
            r'document\.\w+',
            r'window\.\w+',
            r'localStorage',
            r'sessionStorage',
        ]


        dangerous_patterns = [
            (r'\.innerHTML\s*=\s*[^;]*(?:' + '|'.join(user_sources) + r')', 'innerHTML赋值'),
            (r'document\.write\s*\(\s*[^)]*(?:' + '|'.join(user_sources) + r')', 'document.write'),
        ]

        for pattern, location in dangerous_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return {
                    'type': 'stored_xss',
                    'severity': '高危',
                    'location': location,
                    'description': f'检测到{location}使用用户可控输入，存在存储型XSS风险',
                    'evidence': pattern
                }
        return None

    def _detect_dom_xss(self, html: str) -> Optional[Dict]:

        sources = ['location.href', 'location.search', 'location.hash',
                   'document.URL', 'document.documentURI', 'document.baseURI']
        sinks = ['eval', 'innerHTML', 'outerHTML', 'document.write', 'setTimeout', 'setInterval']

        for source in sources:
            for sink in sinks:

                if source in html and sink in html:
                    # 进一步检查是否有数据流
                    if re.search(rf'{re.escape(source)}.*{re.escape(sink)}', html, re.IGNORECASE | re.DOTALL):
                        return {
                            'type': 'dom_xss',
                            'severity': '高危',
                            'location': f'{source} -> {sink}',
                            'description': f'检测到DOM型XSS：{source}数据流入{sink}',
                            'evidence': f'{source} -> {sink}'
                        }
        return None

    def _detect_reflected_xss(self, url: str) -> Optional[Dict]:

        if '?' in url:
            params = url.split('?')[1]
            xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
            for pattern in xss_patterns:
                if pattern in params.lower():
                    return {
                        'type': 'reflected_xss',
                        'severity': '高危',
                        'location': f'URL参数: {params[:50]}',
                        'description': 'URL参数中包含XSS攻击载荷',
                        'evidence': pattern
                    }
        return None

    def _detect_csrf(self, forms: List[FormInfo]) -> Optional[Dict]:
        """检测CSRF"""
        for form in forms:
            if form.has_password and form.method == 'POST':

                return {
                    'type': 'csrf',
                    'severity': '中危',
                    'location': f'表单: {form.action}',
                    'description': '敏感操作表单可能缺少CSRF防护',
                    'evidence': 'POST表单无Token'
                }
        return None

    def _detect_cookie_issues(self, html: str) -> List[Dict]:

        issues = []
        return issues

    def _detect_info_leak(self, html: str) -> Optional[Dict]:

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        phone_pattern = r'1[3-9]\d{9}'

        emails = re.findall(email_pattern, html)
        phones = re.findall(phone_pattern, html)

        if emails or phones:
            return {
                'type': 'info_leak',
                'severity': '低危',
                'location': '页面内容',
                'description': f'页面泄露敏感信息：{len(emails)}个邮箱，{len(phones)}个手机号',
                'evidence': f'邮箱: {emails[:3]}, 手机号: {phones[:3]}'
            }
        return None



    def _detect_js_risks(self, scripts: List[ScriptInfo]) -> List[str]:

        risks = []
        for s in scripts:
            if s.uses_eval:
                risks.append("低危: 页面使用eval()，存在代码注入风险")
            if s.uses_innerhtml:
                risks.append("低危: 页面使用innerHTML，可能存在XSS风险")
            if s.uses_document_write:
                risks.append("低危: 页面使用document.write，可能存在XSS风险")
        return risks

    def _calc_risk_score(self, vulnerabilities: List[Dict], issues: List[str] = None) -> int:
        """计算风险评分"""
        score = 0
        severity_scores = {
            '严重': 25,
            '高危': 15,
            '中危': 5,
            '低危': 2,
            '信息': 1
        }
        for vuln in vulnerabilities:
            score += severity_scores.get(vuln['severity'], 0)
        # issues也参与计分
        if issues:
            for iss in issues:
                if '高危' in iss:
                    score += 10
                elif '中危' in iss:
                    score += 4
                elif '低危' in iss:
                    score += 1
        return min(score, 100)

    def _get_risk_level(self, score: int) -> str:

        if score >= 60:
            return '高危'
        elif score >= 30:
            return '中危'
        elif score >= 10:
            return '低危'
        else:
            return '安全'
