import os
import subprocess
import sys
from pathlib import Path

import pytest

import config as config_module
from config import config_write_path, load_config, user_config_path


def test_config_starts_without_file(tmp_path: Path):
    config = load_config(tmp_path / "missing.yaml", {})
    assert config.fofa.api_key == ""
    assert config.search.size == 100


def test_preferred_environment_overrides_legacy_alias(tmp_path: Path):
    config = load_config(tmp_path / "missing.yaml", {"FOFA_API_KEY": "preferred", "FOFA_KEY": "legacy", "FOFA_EMAIL": "a@example.test"})
    assert config.fofa.api_key == "preferred"
    assert config.fofa.email == "a@example.test"


def test_legacy_environment_alias(tmp_path: Path):
    config = load_config(tmp_path / "missing.yaml", {"FOFA_KEY": "legacy"})
    assert config.fofa.api_key == "legacy"


def test_yaml_secret_emits_a_visible_warning(tmp_path: Path):
    """A plaintext key in YAML must warn with a category Python shows by default."""
    path = tmp_path / "settings.yaml"
    path.write_text("userinfo:\n  key: old-secret\n", encoding="utf-8")
    with pytest.warns(UserWarning):
        config = load_config(path, {})
    assert config.fofa.api_key == "old-secret"


def test_config_write_path_keeps_source_checkout_compatibility(tmp_path: Path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.example.yaml").write_text("fofa: {}\n", encoding="utf-8")
    assert config_write_path(environ={}, cwd=tmp_path, home=tmp_path, platform="linux") == tmp_path / "config" / "settings.yaml"


def test_installed_cli_uses_writable_platform_user_config(tmp_path: Path):
    cwd = tmp_path / "empty"
    cwd.mkdir()
    assert config_write_path(environ={}, cwd=cwd, home=tmp_path, platform="linux") == tmp_path / ".config" / "cybermap" / "settings.yaml"
    assert user_config_path(environ={}, home=tmp_path, platform="darwin") == (
        tmp_path / "Library" / "Application Support" / "CyberMap" / "settings.yaml"
    )
    assert user_config_path(environ={}, home=tmp_path, platform="win32") == (
        tmp_path / "AppData" / "Roaming" / "CyberMap" / "settings.yaml"
    )


def test_explicit_config_path_has_highest_write_priority(tmp_path: Path):
    explicit = tmp_path / "custom.yaml"
    assert config_write_path(
        environ={"CYBERMAP_CONFIG": str(explicit)}, cwd=tmp_path, home=tmp_path, platform="linux"
    ) == explicit


def test_v2_ai_profile_is_migrated_to_provider_routing_without_serializing_secret(tmp_path: Path):
    path = tmp_path / "settings.yaml"
    path.write_text(
        "userinfo:\n"
        "  api_type: deepseek\n"
        "  base_url: https://api.deepseek.example/v1\n"
        "  model: deepseek-chat\n"
        "  deepseek_api_key: legacy-model-secret\n",
        encoding="utf-8",
    )
    with pytest.warns(UserWarning, match="模型 API 密钥"):
        config = load_config(path, {})
    profile = config.providers["deepseek"]
    assert profile.protocol == "openai_chat"
    assert profile.model == "deepseek-chat"
    assert profile.runtime_api_key == "legacy-model-secret"
    assert "runtime_api_key" not in profile.model_dump()
    assert config.routing.planner == "deepseek"
    assert config.routing.reflector == "deepseek"


def test_provider_api_key_can_be_loaded_from_explicitly_confirmed_yaml(tmp_path: Path):
    path = tmp_path / "settings.yaml"
    path.write_text(
        "providers:\n"
        "  deepseek:\n"
        "    protocol: openai_chat\n"
        "    base_url: https://api.deepseek.example/v1\n"
        "    model: deepseek-test\n"
        "    api_key_env: DEEPSEEK_API_KEY\n"
        "    api_key: local-model-key\n",
        encoding="utf-8",
    )
    with pytest.warns(UserWarning, match="写在配置文件中"):
        config = load_config(path, {})
    profile = config.providers["deepseek"]
    assert profile.api_key == "local-model-key"
    assert "api_key" not in profile.model_dump()


def test_provider_defaults_leave_room_for_long_context_models():
    from config import ProviderProfile

    profile = ProviderProfile(protocol="openai_chat", base_url="https://example.test")
    assert profile.max_output_tokens == 32768
    assert profile.timeout == 120.0


def test_plaintext_yaml_key_warns_under_default_warning_filters(tmp_path: Path):
    """A hidden DeprecationWarning made the secret warning useless; it must survive default filters."""
    path = tmp_path / "settings.yaml"
    path.write_text("shodan:\n  api_key: plain-secret\n", encoding="utf-8")
    env = dict(os.environ, CYBERMAP_CONFIG=str(path), PYTHONWARNINGS="")
    env.pop("SHODAN_API_KEY", None)

    result = subprocess.run(
        [sys.executable, "-c", "import config"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert "UserWarning" in result.stderr
    assert "Shodan" in result.stderr


def test_hunter_key_resolution_prefers_environment_over_yaml(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(config_module, "_keyring_secret", lambda *_args, **_kwargs: "")
    path = tmp_path / "settings.yaml"
    path.write_text("hunter:\n  api_key: yaml-hunter\n", encoding="utf-8")

    with pytest.warns(UserWarning, match="Hunter"):
        preferred = load_config(path, {"HUNTER_API_KEY": "env-hunter"})
    assert preferred.hunter.api_key == "env-hunter"

    with pytest.warns(UserWarning, match="Hunter"):
        fallback = load_config(path, {})
    assert fallback.hunter.api_key == "yaml-hunter"
    assert fallback.hunter.base_url == "https://hunter.qianxin.com"


def test_engine_scope_accepts_three_engines_and_the_merged_scope(tmp_path: Path):
    for value in ("fofa", "shodan", "hunter", "all"):
        path = tmp_path / f"{value}.yaml"
        path.write_text(f"search:\n  engine: {value}\n", encoding="utf-8")
        assert load_config(path, {}).search.engine == value
