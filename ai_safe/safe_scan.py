import os
import re
import math
import json
import hashlib
import fnmatch
from pathlib import Path


class FileAnalyzer:
    # 可疑API
    BAD_APIS = [
        'CreateProcess', 'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
        'OpenProcess', 'TerminateProcess', 'CreateThread',
        'VirtualAlloc', 'VirtualProtect', 'HeapAlloc',
        'CreateFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile',
        'RegOpenKey', 'RegCreateKey', 'RegSetValue',
        'socket', 'connect', 'send', 'recv', 'WSAStartup', 'InternetOpen',
        'URLDownloadToFile',
        'GetSystemDirectory', 'GetWindowsDirectory', 'GetTempPath',
        'LoadLibrary', 'GetProcAddress',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
        'IsDebuggerPresent'
    ]

    # 可疑模式
    BAD_PATTERNS = [
        r'cmd\.exe', r'powershell\.exe',
        r'http://', r'https://',
        r'eval\s*\(', r'exec\s*\(',
        r'CreateObject', r'WScript\.Shell'
    ]

    # 恶意规则
    RULES = [
        {"name": "PS下载执行",
         "pattern": r'powershell.*-enc|Invoke-Expression.*DownloadString',
         "severity": "critical", "desc": "ps下载恶意代码", "cat": "远程执行"},
        {"name": "注册表自启",
         "pattern": r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
         "severity": "high", "desc": "开机自启", "cat": "持久化"},
        {"name": "键盘记录",
         "pattern": r'GetAsyncKeyState.*loop|SetWindowsHookEx.*WH_KEYBOARD',
         "severity": "critical", "desc": "记录按键", "cat": "信息窃取"},
        {"name": "进程注入",
         "pattern": r'VirtualAllocEx.*WriteProcessMemory.*CreateRemoteThread',
         "severity": "critical", "desc": "内存注入", "cat": "注入"},
        {"name": "挖矿",
         "pattern": r'stratum\+tcp|XMRig|cryptonight',
         "severity": "high", "desc": "挖矿特征", "cat": "资源滥用"},
        {"name": "Fork炸弹",
         "pattern": r'%0\s*\|\s*%0|:\s*[a-zA-Z]+\s*%0|:loop|goto\s*:?\s*[a-zA-Z]+',
         "severity": "critical", "desc": "批处理Fork炸弹，耗尽系统资源", "cat": "拒绝服务"},
        {"name": "删除系统文件",
         "pattern": r'del\s+/s\s+/q\s+c:\\windows\\|rd\s+/s\s+/q\s+c:\\|format\s+c:',
         "severity": "critical", "desc": "删除或格式化系统盘", "cat": "数据破坏"},
        {"name": "批处理自删除",
         "pattern": r'del\s+"?\%~f0"|del\s+%0\s*&',
         "severity": "high", "desc": "脚本自删除痕迹", "cat": "反调试/隐蔽"},
        {"name": "VBS脚本恶意代码",
         "pattern": r'CreateObject\(["\']WScript\.Shell|CreateObject\(["\']Scripting\.FileSystemObject',
         "severity": "high", "desc": "VBS恶意脚本", "cat": "脚本"},
        {"name": "禁用任务计划持久化",
         "pattern": r'schtasks\s+/create|at\s+\d+:\d+',
         "severity": "high", "desc": "创建计划任务", "cat": "持久化"},
        {"name": "关闭防火墙",
         "pattern": r'netsh\s+firewall\s+set\s+state\s+off|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off',
         "severity": "critical", "desc": "关闭防火墙", "cat": "系统修改"},
        {"name": "禁用UAC",
         "pattern": r'EnableLUA.*0|ConsentPromptBehaviorAdmin.*0',
         "severity": "critical", "desc": "禁用UAC", "cat": "系统修改"},
    ]

    def __init__(self, max_file_size=104857600, max_strings=1000, whitelist_file=None):
        self.max_sz = max_file_size
        self.max_str = max_strings
        # 白名单文件：扫描器同级目录下的 whitelist.json
        if whitelist_file is None:
            whitelist_file = Path(__file__).parent / "whitelist.json"
        self.whitelist_file = Path(whitelist_file)
        self.whitelist = self._load_whitelist()

    def _load_whitelist(self):
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"paths": [], "hashes": [], "names": []}

    def _save_whitelist(self):
        try:
            self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(self.whitelist, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def add_whitelist_path(self, path: str) -> bool:
        path = str(Path(path).resolve())
        if path not in self.whitelist.get("paths", []):
            self.whitelist.setdefault("paths", []).append(path)
            return self._save_whitelist()
        return False

    def add_whitelist_hash(self, hash_val: str) -> bool:
        hash_val = hash_val.strip().lower()
        if hash_val not in self.whitelist.get("hashes", []):
            self.whitelist.setdefault("hashes", []).append(hash_val)
            return self._save_whitelist()
        return False

    def add_whitelist_name(self, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if pattern not in self.whitelist.get("names", []):
            self.whitelist.setdefault("names", []).append(pattern)
            return self._save_whitelist()
        return False

    def get_whitelist_info(self) -> str:
        return (f"路径: {len(self.whitelist.get('paths', []))} 条 | "
                f"哈希: {len(self.whitelist.get('hashes', []))} 条 | "
                f"文件名: {len(self.whitelist.get('names', []))} 条")

    def is_whitelisted(self, fp) -> tuple:

        p = Path(fp)
        try:
            resolved = str(p.resolve())
        except Exception:
            resolved = str(p)

        # 检查路径白名单
        for wp in self.whitelist.get("paths", []):
            try:
                if resolved == str(Path(wp).resolve()):
                    return True, f"路径白名单: {wp}"
            except Exception:
                if resolved == wp:
                    return True, f"路径白名单: {wp}"

        # 计算哈希并检查
        try:
            file_size = p.stat().st_size
            with open(p, 'rb') as f:
                data = f.read(min(1024 * 1024, file_size))
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()

            for wh in self.whitelist.get("hashes", []):
                wh_lower = wh.lower().strip()
                if md5 == wh_lower or sha256 == wh_lower:
                    return True, f"哈希白名单: {wh_lower[:16]}..."
        except Exception:
            pass

        # 检查文件名白名单（支持*通配符）
        fname = p.name.lower()
        for wn in self.whitelist.get("names", []):
            try:
                if fnmatch.fnmatch(fname, wn.lower()):
                    return True, f"文件名白名单: {wn}"
            except Exception:
                if wn.lower() in fname:
                    return True, f"文件名白名单: {wn}"

        return False, ""

    def analyze_file(self, fp: str) -> dict:
        fp = Path(fp)

        if not fp.exists():
            return {"error": f"文件不存在: {fp}"}

        # 检查白名单
        is_white, reason = self.is_whitelisted(fp)
        if is_white:
            return {
                "whitelisted": True,
                "reason": reason,
                "file_info": self._get_info(fp)
            }

        sz = fp.stat().st_size
        if sz > self.max_sz:
            return {"error": f"文件太大: {sz} bytes (>{self.max_sz})"}

        res = {
            "file_info": self._get_info(fp),
            "strings": [],
            "suspicious_apis": [],
            "suspicious_patterns": [],
            "pe_info": {},
            "entropy": 0.0,
            "risk_indicators": [],
            "rule_matches": []
        }

        # 读文件
        try:
            with open(fp, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {"error": f"读文件失败: {e}"}

        res["strings"] = self._get_strs(data)
        res["suspicious_apis"] = self._find_apis(res["strings"])
        res["suspicious_patterns"] = self._find_patterns(data)
        res["entropy"] = self._calc_ent(data)

        if self._is_pe(data):
            res["pe_info"] = self._parse_pe(data)

        res["rule_matches"] = self._match_rules(data)
        res["risk_indicators"] = self._gen_risks(res)

        return res

    """
           批量扫描文件夹
           callback用于进度通知
           返回结果列表
           """
    def scan_folder(self, folder: str, extensions=None, callback=None) -> list:

        if extensions is None:
            extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd',
                          '.ps1', '.vbs', '.js', '.jar', '.py']

        folder = Path(folder)
        if not folder.exists() or not folder.is_dir():
            return []

        # 收集所有符合扩展名的文件
        files = []
        for ext in extensions:
            files.extend(folder.rglob(f"*{ext}"))
        # 也收集无扩展名的可执行文件
        try:
            for fp in folder.rglob("*"):
                if fp.is_file() and not fp.suffix and not fp.name.startswith('.'):
                    if not any(fp.name == f.name for f in files):
                        files.append(fp)
        except Exception:
            pass

        total = len(files)
        results = []

        for idx, fp in enumerate(files):
            if callback:
                try:
                    should_continue = callback(str(fp), idx, total, None)
                    if should_continue is False:
                        break
                except Exception:
                    pass

            try:
                # 先检查白名单
                is_white, reason = self.is_whitelisted(fp)
                if is_white:
                    if callback:
                        try:
                            callback(str(fp), idx, total,
                                     {"whitelisted": True, "reason": reason})
                        except Exception:
                            pass
                    continue

                res = self.analyze_file(str(fp))
                results.append({"path": str(fp), "result": res})

                if callback:
                    try:
                        callback(str(fp), idx, total, res)
                    except Exception:
                        pass
            except Exception as e:
                results.append({"path": str(fp), "result": {"error": str(e)}})

        return results

    def _match_rules(self, data: bytes) -> list:
        matches = []
        s = data.decode('utf-8', errors='ignore')

        for r in self.RULES:
            try:
                if re.search(r["pattern"], s, re.IGNORECASE):
                    matches.append({
                        "name": r["name"],
                        "severity": r["severity"],
                        "description": r["desc"],
                        "category": r["cat"]
                    })
            except Exception:
                continue

        return matches

    def _get_info(self, fp: Path) -> dict:
        info = {
            "file_name": fp.name,
            "file_path": str(fp.absolute()),
            "file_size": 0,
            "file_extension": fp.suffix.lower(),
            "hashes": {"md5": "", "sha256": ""}
        }
        try:
            info["file_size"] = fp.stat().st_size
            with open(fp, 'rb') as f:
                d = f.read(min(1024 * 1024, info["file_size"]))
                info["hashes"]["md5"] = hashlib.md5(d).hexdigest()
                info["hashes"]["sha256"] = hashlib.sha256(d).hexdigest()
        except Exception:
            pass
        return info

    def _get_strs(self, data: bytes, min_len=4) -> list:
        # ASCII
        ascii_pat = rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}'
        ascii_strs = re.findall(ascii_pat, data)

        # Unicode
        uni_pat = rb'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + rb',}'
        uni_strs = re.findall(uni_pat, data)
        uni_strs = [s.decode('utf-16le', errors='ignore') for s in uni_strs]

        all_strs = []
        for s in ascii_strs:
            try:
                d = s.decode('ascii', errors='ignore')
                if d:
                    all_strs.append(d)
            except Exception:
                pass

        all_strs.extend(uni_strs)

        # 去重限制
        uniq = list(set(all_strs))
        uniq.sort(key=len, reverse=True)
        return uniq[:self.max_str]

    def _find_apis(self, strs: list) -> list:
        found = []
        for api in self.BAD_APIS:
            for s in strs:
                if api.lower() in s.lower():
                    found.append({"api": api, "ctx": s[:50]})
                    break
        return found

    def _find_patterns(self, data: bytes) -> list:
        found = []
        s = data.decode('utf-8', errors='ignore')

        for p in self.BAD_PATTERNS:
            ms = re.finditer(p, s, re.IGNORECASE)
            for m in ms:
                found.append({
                    "pat": p,
                    "match": m.group()[:30],
                    "pos": m.start()
                })
                if len(found) >= 10:
                    break
            if len(found) >= 10:
                break

        return found

    def _calc_ent(self, data: bytes) -> float:
        if not data:
            return 0.0
        ent = 0
        for x in range(256):
            p = float(data.count(bytes([x]))) / len(data)
            if p > 0:
                ent += -p * math.log(p, 2)
        return round(ent, 2)

    def _is_pe(self, data: bytes) -> bool:
        return len(data) >= 2 and data[:2] == b'MZ'

    def _parse_pe(self, data: bytes) -> dict:
        info = {
            "is_pe": True,
            "is_dll": False,
            "is_64": False,
            "entry": 0,
            "base": 0,
            "secs": [],
            "bad_secs": [],
            "imports": []
        }

        try:
            import pefile
            pe = pefile.PE(data=data)

            info["is_dll"] = pe.is_dll()
            try:
                info["is_64"] = pe.PE_TYPE == pefile.OPTIONAL_HEADER_PE_PLUS
            except Exception:
                pass
            info["entry"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            info["base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

            for sec in pe.sections:
                name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                info["secs"].append({
                    "name": name,
                    "va": hex(sec.VirtualAddress),
                    "vs": sec.Misc_VirtualSize,
                    "rs": sec.SizeOfRawData,
                    "ent": round(sec.get_entropy(), 2)
                })

                # 可疑节区
                bad_names = ['UPX', 'ASPack', '.vmp', '.themida']
                for bn in bad_names:
                    if bn.lower() in name.lower():
                        info["bad_secs"].append(name)

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    funcs = []
                    for f in entry.imports:
                        if f.name:
                            funcs.append(f.name.decode('utf-8', errors='ignore'))
                    info["imports"].append({"dll": dll, "funcs": funcs[:10]})

            pe.close()

        except ImportError:
            info["err"] = "pefile 未安装，跳过PE分析"
        except Exception as e:
            info["err"] = str(e)

        return info

    def _gen_risks(self, analysis: dict) -> list:
        risks = []

        # 规则匹配
        rules = analysis.get("rule_matches", [])
        if rules:
            for r in rules:
                lv = {"critical": "致命", "high": "高危"}.get(r["severity"], "中危")
                risks.append(f"[{lv}] {r['name']}: {r['description']}")

        # 熵值
        if analysis.get("entropy", 0) > 7.5:
            risks.append(f"高熵值 ({analysis['entropy']}) - 可能加密/加壳")

        # API
        apis = analysis.get("suspicious_apis", [])
        if len(apis) > 5:
            risks.append(f"可疑API多 ({len(apis)}个)")
        elif len(apis) > 0:
            risks.append(f"可疑API ({len(apis)}个)")

        # 模式
        pats = analysis.get("suspicious_patterns", [])
        if len(pats) > 3:
            risks.append(f"可疑模式 ({len(pats)}处)")

        # PE
        pe = analysis.get("pe_info", {})
        if pe.get("is_pe") and pe.get("bad_secs"):
            risks.append(f"加壳: {', '.join(pe['bad_secs'])}")

        return risks

    def fmt4ai(self, analysis: dict) -> str:
        if "error" in analysis:
            return f"错误: {analysis['error']}"

        if analysis.get("whitelisted"):
            return f"白名单跳过: {analysis.get('reason', 'N/A')}"

        lines = []

        fi = analysis.get("file_info", {})
        lines.append("=" * 40)
        lines.append("文件信息")
        lines.append("=" * 40)
        lines.append(f"名: {fi.get('file_name', 'N/A')}")
        lines.append(f"大小: {fi.get('file_size', 0)} bytes")
        hashes = fi.get("hashes", {})
        lines.append(f"MD5: {hashes.get('md5', 'N/A')}")
        lines.append(f"SHA256: {hashes.get('sha256', 'N/A')}")

        lines.append(f"\n熵值: {analysis.get('entropy', 0)}")

        # 规则匹配
        rules = analysis.get("rule_matches", [])
        if rules:
            lines.append("\n" + "!" * 40)
            lines.append("恶意规则匹配")
            lines.append("!" * 40)
            for r in rules:
                lines.append(f"  [{r['severity'].upper()}] {r['name']}")
                lines.append(f"    {r['description']}")

        # 风险
        risks = analysis.get("risk_indicators", [])
        if risks:
            lines.append("\n" + "=" * 40)
            lines.append("风险")
            lines.append("=" * 40)
            for r in risks:
                lines.append(f"- {r}")

        # API
        apis = analysis.get("suspicious_apis", [])
        if apis:
            lines.append("\n" + "=" * 40)
            lines.append(f"可疑API ({len(apis)}个)")
            lines.append("=" * 40)
            for a in apis[:10]:
                lines.append(f"- {a['api']}: {a['ctx']}")

        # 模式
        pats = analysis.get("suspicious_patterns", [])
        if pats:
            lines.append("\n" + "=" * 40)
            lines.append(f"可疑模式 ({len(pats)}处)")
            lines.append("=" * 40)
            for p in pats[:5]:
                lines.append(f"- {p['match']}")

        # PE
        pe = analysis.get("pe_info", {})
        if pe.get("is_pe"):
            lines.append("\n" + "=" * 40)
            lines.append("PE信息")
            lines.append("=" * 40)
            lines.append(f"类型: {'DLL' if pe.get('is_dll') else 'EXE'}")
            lines.append(f"位数: {'64' if pe.get('is_64') else '32'}")

            secs = pe.get("secs", [])
            if secs:
                lines.append(f"\n节区 ({len(secs)}个):")
                for s in secs:
                    lines.append(f"  - {s['name']}: {s['rs']} bytes, ent={s['ent']}")

        # 字符串
        strs = analysis.get("strings", [])
        if strs:
            lines.append("\n" + "=" * 40)
            lines.append(f"字符串 ({len(strs)}个)")
            lines.append("=" * 40)
            for s in strs[:20]:
                if len(s) > 80:
                    s = s[:80] + "..."
                lines.append(f"  {s}")

        return "\n".join(lines)
