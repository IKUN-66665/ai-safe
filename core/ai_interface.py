import yaml
import json
import re
from pathlib import Path


class OllamaProvider:
    def __init__(self, host="http://localhost:11434", model="deepseek-r1:7b",
                 tmp=0.1, mt=4096):
        self.host = host
        self.model = model
        self.tmp = tmp
        self.mt = mt
        self._ok = False

    def is_available(self):
        try:
            import requests
            r = requests.get(f"{self.host}/api/tags", timeout=5)
            if r.status_code == 200:
                names = [m.get("name", "") for m in r.json().get("models", [])]
                self._ok = any(self.model in n for n in names)
        except:
            self._ok = False
        return self._ok

    def analyze(self, prompt, text):
        import requests
        payload = {
            "model": self.model,
            "prompt": f"{prompt}\n\n{text}",
            "stream": False,
            "options": {"temperature": self.tmp, "num_predict": self.mt}
        }
        r = requests.post(f"{self.host}/api/generate", json=payload, timeout=300)
        r.raise_for_status()
        raw = r.json().get("response", "")

        # 解析JSON，不行就正则抠
        try:
            return json.loads(raw)
        except:
            m = re.search(r'\{[\s\S]*\}', raw)
            if m:
                try:
                    return json.loads(m.group())
                except:
                    pass
            return {"raw_response": raw, "error": "AI返回格式解析失败"}


class AIManager:
    def __init__(self, **kwargs):
        self.provider = OllamaProvider(**kwargs)

    def analyze(self, prompt, text):
        return self.provider.analyze(prompt, text)

    def check_health(self):
        if self.provider.is_available():
            return {"status": "healthy", "model": self.provider.model}
        return {"status": "unhealthy", "model": self.provider.model}


def create_ai_manager(cfg_path: str):
    with open(cfg_path, 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f)

    ol = cfg.get('ai', {}).get('ollama', {})
    return AIManager(
        host=ol.get('host', 'http://localhost:11434'),
        model=ol.get('model', 'deepseek-r1:7b'),
        tmp=ol.get('temperature', 0.1),
        mt=ol.get('max_tokens', 4096)
    )
