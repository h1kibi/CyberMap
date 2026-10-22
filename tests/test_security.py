import codecs
import hashlib
import socket

import httpx
import mmh3
import pytest

from core.engines import favicon_query
from utils.helpers import IconHashCalculator, assert_public_http_url, is_blocked_ssrf_address


@pytest.mark.parametrize("target", ["127.0.0.1", "http://[::1]", "http://10.0.0.1"])
def test_private_targets_can_be_opted_out(target):
    with pytest.raises(ValueError, match="私网"):
        assert_public_http_url(target, allow_private=False)


def test_private_lan_is_allowed_but_cloud_metadata_stays_blocked():
    assert assert_public_http_url("http://192.168.1.1/", allow_private=True) == "http://192.168.1.1/"
    assert assert_public_http_url("http://10.0.0.8/", allow_private=True) == "http://10.0.0.8/"
    assert is_blocked_ssrf_address("10.0.0.1", allow_private=True) is False
    with pytest.raises(ValueError, match="云元数据"):
        assert_public_http_url("http://169.254.169.254/latest/meta-data", allow_private=True)
    with pytest.raises(ValueError, match="云元数据"):
        assert_public_http_url("http://100.100.100.200/", allow_private=True)


def test_clash_fake_ip_is_not_treated_as_ssrf(monkeypatch):
    def fake_addrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.56", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_addrinfo)
    assert is_blocked_ssrf_address("198.18.0.56") is False
    assert is_blocked_ssrf_address("10.0.0.1") is True
    assert assert_public_http_url("https://www.baidu.com/", allow_private=False) == "https://www.baidu.com/"


def test_local_icon_file_uses_the_same_hash_pipeline(tmp_path):
    icon = tmp_path / "favicon.ico"
    icon.write_bytes(b"not-a-real-icon-but-stable-test-content")

    digest = IconHashCalculator.hash_file(str(icon))
    assert digest == IconHashCalculator.hash_bytes(icon.read_bytes())
    content = icon.read_bytes()
    # One read of the bytes serves every engine: FOFA/Shodan filter on the MurmurHash3 of the
    # base64 form, Hunter filters on the MD5 of the file itself (verified against the live API).
    assert digest.murmur3 == mmh3.hash(codecs.lookup("base64").encode(content)[0])
    assert digest.md5 == hashlib.md5(content, usedforsecurity=False).hexdigest()
    assert favicon_query("fofa", digest) == f'icon_hash="{digest.murmur3}"'
    assert favicon_query("shodan", digest) == f"http.favicon.hash:{digest.murmur3}"
    assert favicon_query("hunter", digest) == f'web.icon="{digest.md5}"'


def test_local_icon_file_is_bounded(tmp_path, monkeypatch):
    icon = tmp_path / "large.ico"
    icon.write_bytes(b"12345")
    monkeypatch.setattr(IconHashCalculator, "MAX_ICON_BYTES", 4)

    with pytest.raises(ValueError, match="4 MiB"):
        IconHashCalculator.hash_file(str(icon))


def _patch_async_client(monkeypatch, handler):
    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_icon_hash_follows_cdn_redirect(monkeypatch):
    monkeypatch.setattr(
        "utils.helpers.assert_public_http_url",
        lambda url, **_kwargs: url if "://" in url else f"https://{url}",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.qq.com":
            return httpx.Response(301, headers={"Location": "https://mat1.gtimg.com/qqcdn/xw/favicon.ico"})
        if request.url.host == "mat1.gtimg.com":
            return httpx.Response(200, content=b"not-a-real-icon-but-stable-test-content")
        return httpx.Response(404)

    _patch_async_client(monkeypatch, handler)
    result = await IconHashCalculator.hash_url("https://www.qq.com")
    assert result == IconHashCalculator.hash_bytes(b"not-a-real-icon-but-stable-test-content")


@pytest.mark.asyncio
async def test_icon_hash_rejects_metadata_redirect(monkeypatch):
    def fake_assert(url: str, **_kwargs) -> str:
        if "169.254.169.254" in url:
            raise ValueError("已拦截云元数据目标")
        return url if "://" in url else f"https://{url}"

    monkeypatch.setattr("utils.helpers.assert_public_http_url", fake_assert)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    _patch_async_client(monkeypatch, handler)
    assert await IconHashCalculator.hash_url("https://www.example.com") is None


def test_transport_loggers_stay_quiet_when_the_host_enables_info_logging():
    """Every engine passes its key in the query string and httpx logs full URLs at INFO."""
    import logging

    import utils.logger  # noqa: F401 - importing the logging module applies the transport pin

    root = logging.getLogger()
    original = root.level
    root.setLevel(logging.INFO)  # a service host that turns on INFO logging must still not leak
    try:
        assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
        assert not logging.getLogger("httpcore").isEnabledFor(logging.INFO)
    finally:
        root.setLevel(original)
