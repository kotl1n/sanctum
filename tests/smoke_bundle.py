"""Сборка и проверка полного комплекта во временном домашнем каталоге без запроса к модели."""
import json, os, select, subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "scripts"))
from cli_text import ArgumentParser
from package_release import package
from install import Installer, PLUGIN, CONFIG
from manage_backend import load, check, set_enabled
parser = ArgumentParser(description=__doc__)
parser.add_argument('--backend', type=Path, required=True, help='Каталог закреплённой серверной части')
parser.add_argument('--output', type=Path, required=True, help='Новый каталог для проверяемого комплекта')
args = parser.parse_args()
bundle = args.output.absolute()
package(args.backend.resolve(), bundle)
with tempfile.TemporaryDirectory(prefix="sanctum-release-home-") as temporary:
    home = Path(temporary)
    with Installer(home) as installer:
        result = installer.install(bundle, apply=True)
        assert result["status"] == "staged"
        profile = load(bundle / "plugin/ui/desktop-compatibility.json")
        assert check(home, profile)["compatible"]
        set_enabled(home, profile, True, apply=True)
        env = dict(os.environ)
        for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY", "CHATGPT_AUTH_TOKEN"):
            env.pop(name, None)
        env.update(HOME=str(home), CODEX_HOME=str(home / ".codex"),
            XDG_CONFIG_HOME=str(home / ".config"), XDG_STATE_HOME=str(home / ".local/state"),
            SANCTUM_STATE_DIR=str(home / ".local/state/sanctum-portless"),
            SANCTUM_SETTINGS_PATH=str(home / CONFIG / "settings.json"),
            SANCTUM_GUARD_POLICY=str(home / CONFIG / "policy.json"),
            SANCTUM_BACKEND_ROUTE=str(home / CONFIG / "backend.json"),
            SANCTUM_CONTEXT_PROTECTION="1", SANCTUM_VERIFY_COMPATIBILITY="1", SANCTUM_PORTLESS_ACTIVE="1")
        guard = home / PLUGIN / "bin/sanctum-guard"
        def guard_json(command, value):
            result = subprocess.run([str(guard), command], input=json.dumps(value), env=env,
                capture_output=True, text=True, timeout=20, check=True)
            return json.loads(result.stdout)
        safe = guard_json("model-request", {"session_id":"release-smoke", "request_id":"fixture-1", "body":{
            "model":"fixture-model", "instructions":"Local synthetic fixture", "input":"Connect 192.0.2.10"}})
        assert "192.0.2.10" not in json.dumps(safe)
        restored = guard_json("hook", {"hook_event_name":"PreToolUse", "session_id":"release-smoke",
            "tool_name":"read_file", "tool_input":{"path":"/tmp/[IP-1]"}})
        assert restored["hookSpecificOutput"]["updatedInput"]["path"] == "/tmp/192.0.2.10"
        blocked = guard_json("hook", {"hook_event_name":"PreToolUse", "session_id":"release-smoke",
            "tool_name":"read_file", "tool_input":{"path":"/tmp/[IP-999]"}})
        assert blocked["decision"] == "block"
        adapter = home / PLUGIN / "bin/sanctum-codex"
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen([str(adapter), "app-server", "--listen", "stdio://"],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
            try:
                process.stdin.write(json.dumps({"id":1,"method":"initialize","params":{
                    "clientInfo":{"name":"sanctum-release-check","version":"1.0.0"},
                    "capabilities":{"experimentalApi":True}}}) + "\n")
                process.stdin.flush()
                ready, _, _ = select.select([process.stdout], [], [], 30)
                assert ready, "app_server_initialize_timeout"
                line = process.stdout.readline()
                assert line, "app_server_exited_before_initialize"
                response = json.loads(line)
                assert response.get("id") == 1 and "result" in response, "app_server_initialize_failed"
                print("Инициализация нативного app-server: успешно")
            finally:
                process.stdin.close()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        assert installer.uninstall(apply=True)["status"] == "removed"
        assert not guard.exists()
        assert load(home / CONFIG / "settings.json")["enabled"] is True
print("Установка, совместимость, маскирование, локальное восстановление и удаление полного комплекта: успешно")
print("Комплект:", bundle)
