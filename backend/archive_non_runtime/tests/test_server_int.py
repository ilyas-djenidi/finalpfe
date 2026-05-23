from pathlib import Path

from scanners.server_int import run_server_config_scan


def test_detect_server_tokens_full(tmp_path: Path):
    conf = tmp_path / "httpd.conf"
    conf.write_text("ServerTokens Full\n", encoding="utf-8")
    result = run_server_config_scan(str(conf))
    checks = {v.get("check") for v in result.get("vulnerabilities", [])}
    assert "insecure_server_tokens" in checks


def test_safe_minimal_config_no_critical(tmp_path: Path):
    conf = tmp_path / "httpd.conf"
    conf.write_text(
        "\n".join(
            [
                "ServerTokens Prod",
                "ServerSignature Off",
                "TraceEnable Off",
                "LimitRequestLine 8190",
                "LimitRequestFields 100",
                "LimitRequestFieldSize 8190",
                "LimitRequestBody 10485760",
                "FileETag MTime Size",
                "KeepAlive On",
                "KeepAliveTimeout 5",
                "MaxKeepAliveRequests 100",
                "MaxRequestWorkers 400",
                "MaxConnectionsPerChild 10000",
                "LogLevel warn",
            ]
        ),
        encoding="utf-8",
    )
    result = run_server_config_scan(str(conf))
    criticals = [v for v in result.get("vulnerabilities", []) if v.get("severity") == "critical"]
    assert len(criticals) == 0
