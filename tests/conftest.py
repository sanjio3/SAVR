"""全局测试夹具。

LLM 响应缓存（src/core/llm_cache.py）默认开启，且以 provider|model|messages|... 为键。
LLM 调用层单测（如 test_c2_llm_stream）会用同一组 system/messages 反复调用**不同**的
mock 服务，此时键相同 → 命中上一个用例的缓存响应，造成跨用例串味（返回 'foo-bar' 之类的
陈旧值）。生产环境每个扫描是独立进程、各家 provider/model 与提示词各异，不受此影响。

因此在测试里统一关闭缓存，保证用例隔离；需要验证缓存行为时由用例自行设置该环境变量。
"""
import pytest


@pytest.fixture(autouse=True)
def _disable_llm_cache(monkeypatch):
    monkeypatch.setenv("SAST_AI_LLM_CACHE", "0")
