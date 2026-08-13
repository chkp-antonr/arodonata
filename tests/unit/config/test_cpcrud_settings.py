# tests/unit/config/test_cpcrud_settings.py
from arodonata.config.settings import ArodonataSettings


def test_cpcrud_defaults():
    s = ArodonataSettings(mgmt_names="m1", mgmt_servers="10.0.0.1", api_keys="k")
    assert s.cpcrud_on_name_conflict == "update"
    assert s.cpcrud_on_ip_conflict == "reuse"
    assert s.cpcrud_auto_name_prefix_host == "Host_"
    assert s.cpcrud_auto_name_prefix_network == "Net_"
    assert s.cpcrud_auto_name_prefix_range == "IPR_"
    assert s.cpcrud_auto_name_prefix_svc_tcp == "TCP_"
    assert s.cpcrud_auto_name_prefix_svc_udp == "UDP_"
    assert s.cpcrud_auto_name_prefix_svc_icmp == "ICMP_"
    assert s.cpcrud_refresh_mode == "invalidate"
    assert s.cpcrud_schema_path == ""


def test_cpcrud_env_override(monkeypatch):
    monkeypatch.setenv("ARODONATA_CPCRUD_ON_IP_CONFLICT", "error")
    s = ArodonataSettings(mgmt_names="m1", mgmt_servers="10.0.0.1", api_keys="k")
    assert s.cpcrud_on_ip_conflict == "error"


def test_cpcrud_env_overrides(monkeypatch):
    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP", "Icmp-")
    monkeypatch.setenv("ARODONATA_CPCRUD_REFRESH_MODE", "force")
    s = ArodonataSettings(mgmt_names="m1", mgmt_servers="10.0.0.1", api_keys="k")
    assert s.cpcrud_auto_name_prefix_svc_icmp == "Icmp-"
    assert s.cpcrud_refresh_mode == "force"
