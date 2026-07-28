"""direct_first.py — динамический NO_PROXY (#197): candidate-домены (z.ai BUILTIN + user config)
проверяются честным прямым TLS-test (sys_probe.direct_probe, вынесен из #206), reachable →
попадают в NO_PROXY. Resilience: смерть VPS не роняет direct-домены. Канон zai-direct-no-proxy
(z.ai всегда в NO_PROXY), verify-dont-guess (честный HTTP-ответ, не TCP-only), merge не replace.
"""
import json

import direct_first


# ============================ candidate_domains ============================

def test_candidate_domains_builtin_zai_always_present(tmp_path):
    p = tmp_path / "missing.json"
    domains = direct_first.candidate_domains(path=p)
    assert "z.ai" in domains


def test_candidate_domains_user_config_merged(tmp_path):
    p = tmp_path / "srouter.local.json"
    p.write_text(json.dumps({"schema_version": 1, "direct_domains": ["api.example.com"]}), encoding="utf-8")
    domains = direct_first.candidate_domains(path=p)
    assert "z.ai" in domains
    assert "api.example.com" in domains


def test_candidate_domains_invalid_dropped(tmp_path):
    p = tmp_path / "srouter.local.json"
    p.write_text(json.dumps({"schema_version": 1, "direct_domains": ["; rm -rf /", "ok.example.com"]}),
                 encoding="utf-8")
    domains = direct_first.candidate_domains(path=p)
    assert "; rm -rf /" not in domains
    assert "ok.example.com" in domains


def test_candidate_domains_dedup_case_insensitive(tmp_path):
    p = tmp_path / "srouter.local.json"
    p.write_text(json.dumps({"schema_version": 1, "direct_domains": ["Z.AI", "z.ai"]}), encoding="utf-8")
    domains = direct_first.candidate_domains(path=p)
    assert sum(1 for d in domains if d.lower() == "z.ai") == 1


def test_candidate_domains_never_raises_on_broken_state(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    domains = direct_first.candidate_domains(path=p)
    assert "z.ai" in domains


# ============================ direct_reachable (делегирует sys_probe.direct_probe) ============================

def test_direct_reachable_delegates_to_sys_probe(monkeypatch):
    captured = {}

    def fake_direct_probe(host, **kwargs):
        captured["host"] = host
        return {"reachable": True, "kind": "ok"}

    monkeypatch.setattr(direct_first.sys_probe, "direct_probe", fake_direct_probe)
    ok, kind = direct_first.direct_reachable("z.ai")
    assert ok is True
    assert kind == "ok"
    assert captured["host"] == "z.ai"


def test_direct_reachable_blocked(monkeypatch):
    monkeypatch.setattr(direct_first.sys_probe, "direct_probe",
                        lambda host, **kwargs: {"reachable": False, "kind": "timeout"})
    ok, kind = direct_first.direct_reachable("github.com")
    assert ok is False
    assert kind == "timeout"


# ============================ detect ============================

def test_detect_zai_reachable_goes_to_reachable_list(tmp_path, monkeypatch):
    p = tmp_path / "missing.json"
    monkeypatch.setattr(direct_first.sys_probe, "direct_probe",
                        lambda host, **kwargs: {"reachable": True, "kind": "ok"})
    det = direct_first.detect(path=p)
    assert "z.ai" in det["reachable"]
    assert det["blocked"] == []


def test_detect_gfw_blocked_domain_goes_to_blocked_list(tmp_path, monkeypatch):
    p = tmp_path / "srouter.local.json"
    p.write_text(json.dumps({"schema_version": 1, "direct_domains": ["cut.example.com"]}), encoding="utf-8")

    def fake_direct_probe(host, **kwargs):
        if host == "cut.example.com":
            return {"reachable": False, "kind": "timeout"}
        return {"reachable": True, "kind": "ok"}

    monkeypatch.setattr(direct_first.sys_probe, "direct_probe", fake_direct_probe)
    det = direct_first.detect(path=p)
    assert "z.ai" in det["reachable"]
    assert "cut.example.com" in det["blocked"]
    assert "cut.example.com" not in det["reachable"]


def test_detect_never_raises_when_probe_throws(tmp_path, monkeypatch):
    p = tmp_path / "missing.json"

    def boom(host, **kwargs):
        raise RuntimeError("network exploded")

    monkeypatch.setattr(direct_first.sys_probe, "direct_probe", boom)
    det = direct_first.detect(path=p)
    assert isinstance(det, dict)
    assert det["reachable"] == []
    assert "z.ai" in det["blocked"]


# ============================ build_no_proxy ============================

def test_build_no_proxy_loopback_plus_domains():
    s = direct_first.build_no_proxy(["z.ai"])
    assert s == "localhost,127.0.0.1,::1,z.ai,.z.ai"


def test_build_no_proxy_subdomain_suffix_for_user_domain():
    s = direct_first.build_no_proxy(["api.example.com"])
    assert "api.example.com" in s.split(",")
    assert ".api.example.com" in s.split(",")


def test_build_no_proxy_zai_always_included_even_if_not_in_reachable():
    """Канон zai-direct-no-proxy: z.ai в NO_PROXY БЕЗУСЛОВНО, даже если detect его не подтвердил."""
    s = direct_first.build_no_proxy([])
    assert "z.ai" in s.split(",")
    assert ".z.ai" in s.split(",")


def test_build_no_proxy_empty_list_still_has_loopback_and_zai():
    s = direct_first.build_no_proxy([])
    assert s.startswith("localhost,127.0.0.1,::1,")


# ============================ no_proxy_string ============================

def test_no_proxy_string_returns_built_string(tmp_path, monkeypatch):
    p = tmp_path / "missing.json"
    monkeypatch.setattr(direct_first.sys_probe, "direct_probe",
                        lambda host, **kwargs: {"reachable": True, "kind": "ok"})
    s = direct_first.no_proxy_string(path=p)
    assert "z.ai" in s.split(",")
    assert "localhost" in s.split(",")


def test_no_proxy_string_fallback_on_exception(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("state corrupted")

    monkeypatch.setattr(direct_first, "detect", boom)
    s = direct_first.no_proxy_string()
    assert s == direct_first.BUILTIN_FALLBACK_NO_PROXY


# ============================ merge_with_existing ============================

def test_merge_with_existing_preserves_foreign_hosts(tmp_path, monkeypatch):
    p = tmp_path / "missing.json"
    monkeypatch.setattr(direct_first.sys_probe, "direct_probe",
                        lambda host, **kwargs: {"reachable": True, "kind": "ok"})
    merged = direct_first.merge_with_existing("corp.internal", path=p)
    hosts = merged.split(",")
    assert "corp.internal" in hosts
    assert "z.ai" in hosts


def test_merge_with_existing_dedup_case_insensitive(tmp_path, monkeypatch):
    p = tmp_path / "missing.json"
    monkeypatch.setattr(direct_first.sys_probe, "direct_probe",
                        lambda host, **kwargs: {"reachable": True, "kind": "ok"})
    merged = direct_first.merge_with_existing("Z.AI,localhost", path=p)
    hosts_lower = [h.lower() for h in merged.split(",")]
    assert hosts_lower.count("z.ai") == 1
