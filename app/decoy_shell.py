from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Dict, List, Optional, Tuple

import requests

from app.config import OLLAMA_BASE_URL, OLLAMA_FALLBACK_URLS, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from app.state import get_session_snapshot, touch_session, update_session_metadata


def _build_ollama_urls() -> list[str]:
    urls = [OLLAMA_BASE_URL, *OLLAMA_FALLBACK_URLS]
    return list(dict.fromkeys(urls))


def _normalize_command(command: str) -> str:
    return command.strip()


def _session_key(metadata: Optional[Dict[str, object]], event_id: Optional[str]) -> str:
    metadata = metadata or {}
    client_ip = str(metadata.get("client_ip") or "unknown")
    user_agent = str(metadata.get("user_agent") or "")
    agent_hash = sha256(user_agent.encode("utf-8")).hexdigest()[:10] if user_agent else "noagent"
    if client_ip == "unknown" and agent_hash == "noagent":
        suffix = event_id or "global"
        return f"it_decoy::{suffix[:8]}"
    return f"it_decoy::{client_ip}::{agent_hash}"


def _looks_windows(command: str, state: Dict[str, object]) -> bool:
    shell_family = str(state.get("shell_family") or "")
    if shell_family == "windows":
        return True
    lowered = command.lower()
    return any(
        token in lowered
        for token in [
            "powershell",
            "cmd.exe",
            "ipconfig",
            "certutil",
            "net user",
            "whoami /all",
            "tasklist",
            "dir ",
            "type ",
        ]
    )


def _default_state(command: str, metadata: Optional[Dict[str, object]]) -> Dict[str, object]:
    windows = _looks_windows(command, {"shell_family": ""})
    if windows:
        return {
            "shell_family": "windows",
            "hostname": "WIN-SRV-02",
            "username": "svc-backup",
            "cwd": "C:\\Users\\svc-backup",
            "banner": "Microsoft Windows [Version 10.0.20348.2402]",
            "prompt_symbol": ">",
            "prompt_prefix": "PS ",
            "last_exit_code": 0,
            "history": [],
            "last_command": "",
            "last_output": "",
        }

    return {
        "shell_family": "linux",
        "hostname": "app-server-02",
        "username": "ubuntu",
        "cwd": "/var/www/html",
        "banner": "Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-1051-azure x86_64)",
        "prompt_symbol": "$",
        "prompt_prefix": "",
        "last_exit_code": 0,
        "history": [],
        "last_command": "",
        "last_output": "",
    }


def _load_state(session_key: str, command: str, metadata: Optional[Dict[str, object]]) -> Dict[str, object]:
    snapshot = get_session_snapshot(session_key)
    if snapshot and snapshot.metadata.get("shell_state"):
        try:
            state = json.loads(snapshot.metadata["shell_state"])
            if isinstance(state, dict):
                return state
        except json.JSONDecodeError:
            pass

    return _default_state(command=command, metadata=metadata)


def _persist_state(session_key: str, state: Dict[str, object], metadata: Optional[Dict[str, object]]) -> None:
    update_metadata: Dict[str, str] = {
        "shell_state": json.dumps(state, ensure_ascii=True),
    }
    if metadata:
        for key in ["client_ip", "user_agent", "path", "method"]:
            value = metadata.get(key)
            if value is not None:
                update_metadata[key] = str(value)
    touch_session(
        session_key,
        trap="ollama_decoy",
        target_domain="IT",
        metadata=update_metadata,
    )


def _prompt(state: Dict[str, object]) -> str:
    if state.get("shell_family") == "windows":
        return f"{state.get('prompt_prefix', '')}{state.get('cwd', 'C:\\Users\\svc-backup')}{state.get('prompt_symbol', '>')}"
    return f"{state.get('username', 'ubuntu')}@{state.get('hostname', 'app-server-02')}:{state.get('cwd', '/var/www/html')}{state.get('prompt_symbol', '$')}"


def _split_pipeline(command: str) -> List[str]:
    parts = [chunk.strip() for chunk in re.split(r"\s*(?:&&|;)\s*", command) if chunk.strip()]
    return parts or [command.strip()]


def _should_use_llm_fallback(command: str, state: Dict[str, object]) -> bool:
    lowered = command.strip().lower()
    if not lowered:
        return False

    shell_family = str(state.get("shell_family") or "")
    shell_tokens = {
        "linux": ["pwd", "whoami", "hostname", "id", "ls", "cat ", "ip a", "ifconfig", "ps ", "history", "echo ", "cd ", "uname", "date", "uptime", "df ", "free ", "ip route", "netstat", "ss "],
        "windows": ["whoami", "hostname", "$env:computername", "pwd", "dir", "ipconfig", "tasklist", "certutil", "type ", "echo ", "cd ", "cls"],
    }

    tokens = shell_tokens.get(shell_family, shell_tokens["linux"])
    if any(lowered == token or lowered.startswith(token) for token in tokens):
        return False

    if any(marker in lowered for marker in ["|", ">", "<", "&&", ";"]):
        return False

    if len(lowered.split()) >= 4:
        return True

    natural_language_hints = [
        "show me",
        "tell me",
        "list",
        "explain",
        "what is",
        "how do",
        "give me",
        "current",
        "running",
        "status",
        "routes",
        "processes",
        "files",
        "network",
    ]
    return any(hint in lowered for hint in natural_language_hints)


def _handle_linux_command(state: Dict[str, object], command: str) -> Tuple[List[str], int]:
    lowered = command.lower()
    cwd = str(state.get("cwd", "/var/www/html"))
    user = str(state.get("username", "ubuntu"))
    host = str(state.get("hostname", "app-server-02"))

    if lowered in {"", "clear"}:
        return [], 0
    if lowered == "pwd":
        return [cwd], 0
    if lowered == "whoami":
        return [user], 0
    if lowered == "hostname":
        return [host], 0
    if lowered in {"date", "date -u"}:
        return ["Fri Aug 07 10:58:32 UTC 2026"], 0
    if lowered == "uptime":
        return [" 10:58:32 up 12 days,  4:17,  2 users,  load average: 0.12, 0.08, 0.04"], 0
    if lowered in {"uname -a", "uname -r"}:
        return [f"Linux {host} 5.15.0-1051-azure #59-Ubuntu SMP Fri Feb 16 16:16:00 UTC 2024 x86_64 GNU/Linux"], 0
    if lowered == "id":
        return [f"uid=1001({user}) gid=1001({user}) groups=1001({user}),27(sudo)"], 0
    if lowered.startswith("cd "):
        target = command[3:].strip().strip('"\'')
        if target in {"", "~"}:
            state["cwd"] = f"/home/{user}"
            return [], 0
        if target == "..":
            parent = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
            state["cwd"] = parent
            return [], 0
        if target.startswith("/"):
            state["cwd"] = target.rstrip("/") or "/"
            return [], 0
        state["cwd"] = f"{cwd.rstrip('/')}/{target}".replace("//", "/")
        return [], 0
    if lowered.startswith("ls"):
        return [
            "app.py  logs/  static/  templates/",
            "README.md  requirements.txt  .env",
        ], 0
    if lowered.startswith("cat /etc/os-release"):
        return [
            'NAME="Ubuntu"',
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"',
            'ID=ubuntu',
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
        ], 0
    if lowered.startswith("ip a") or lowered.startswith("ifconfig"):
        return [
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500",
            "    inet 10.20.30.15/24 brd 10.20.30.255 scope global eth0",
            "3: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500",
            "    inet 172.20.88.11/24 scope global tun0",
        ], 0
    if lowered.startswith("ps aux"):
        return [
            "root         1  0.0  0.2  18532  3140 ?        Ss   08:00   0:01 /sbin/init",
            "ubuntu      42  0.1  1.0  78244 21400 ?        Sl   08:02   0:04 python3 app.py",
            "root        77  0.0  0.5  61240 11024 ?        Ss   08:03   0:00 /usr/bin/ssh -D",
        ], 0
    if lowered.startswith("netstat -an") or lowered.startswith("ss -tulpn"):
        return [
            "tcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*",
            "tcp   LISTEN 0      4096   0.0.0.0:80      0.0.0.0:*",
        ], 0
    if lowered.startswith("ip route"):
        return [
            "default via 10.20.30.1 dev eth0 proto dhcp src 10.20.30.15 metric 100",
            "10.20.30.0/24 dev eth0 proto kernel scope link src 10.20.30.15",
            "172.20.88.0/24 dev tun0 proto kernel scope link src 172.20.88.11",
        ], 0
    if lowered.startswith("df -h"):
        return [
            "Filesystem      Size  Used Avail Use% Mounted on",
            "/dev/sda1        59G   18G   39G  32% /",
            "tmpfs           3.9G     0  3.9G   0% /dev/shm",
        ], 0
    if lowered.startswith("free -m"):
        return [
            "              total        used        free      shared  buff/cache   available",
            "Mem:           7874        2310        3981         122        1582        5231",
            "Swap:          2047           0        2047",
        ], 0
    if lowered.startswith("history"):
        history = state.get("history", [])[-10:]
        lines = [f"{index + 1}  {entry}" for index, entry in enumerate(history)]
        return lines or [""], 0
    if lowered.startswith("echo "):
        return [command[5:].strip().strip('"\'')], 0

    return [f"bash: {command.split()[0]}: command not found"], 127


def _handle_windows_command(state: Dict[str, object], command: str) -> Tuple[List[str], int]:
    lowered = command.lower()
    cwd = str(state.get("cwd", "C:\\Users\\svc-backup"))
    user = str(state.get("username", "svc-backup"))
    host = str(state.get("hostname", "WIN-SRV-02"))

    if lowered in {"", "cls"}:
        return [], 0
    if lowered == "whoami":
        return [f"{host}\\{user}"], 0
    if lowered in {"hostname", "$env:computername"}:
        return [host], 0
    if lowered == "pwd":
        return [f"Path\n----\n{cwd}"], 0
    if lowered.startswith("cd "):
        target = command[3:].strip().strip('"\'')
        if target == "..":
            parent = "\\".join(cwd.rstrip("\\").split("\\")[:-1]) or "C:\\"
            state["cwd"] = parent
            return [], 0
        if re.match(r"^[A-Za-z]:\\", target):
            state["cwd"] = target.rstrip("\\")
            return [], 0
        state["cwd"] = f"{cwd.rstrip('\\')}\\{target}".replace("\\\\", "\\")
        return [], 0
    if lowered.startswith("dir"):
        return [
            " Volume in drive C has no label.",
            " Directory of C:\\Users\\svc-backup",
            "",
            "08/07/2026  08:10 AM    <DIR>          .ssh",
            "08/07/2026  08:10 AM    <DIR>          Desktop",
            "08/07/2026  08:10 AM               512 notes.txt",
        ], 0
    if lowered.startswith("ipconfig"):
        return [
            "Ethernet adapter Ethernet0:",
            "   IPv4 Address. . . . . . . . . . . : 10.20.30.45",
            "   Default Gateway . . . . . . . . . : 10.20.30.1",
        ], 0
    if lowered.startswith("tasklist"):
        return [
            "Image Name                     PID Session Name        Mem Usage",
            "System                           4 Services                   8 K",
            "svchost.exe                   1100 Services              24,000 K",
            "conhost.exe                   2480 Console                 7,200 K",
        ], 0
    if lowered.startswith("certutil"):
        return ["CertUtil: -decode command completed successfully."], 0
    if lowered.startswith("type "):
        return ["Access is denied."], 5
    if lowered.startswith("echo "):
        return [command[5:].strip().strip('"\'')], 0

    return [f"'{command.split()[0]}' is not recognized as an internal or external command,"], 9009


def _deterministic_shell_reply(state: Dict[str, object], command: str) -> Tuple[List[str], int]:
    if state.get("shell_family") == "windows":
        return _handle_windows_command(state, command)
    return _handle_linux_command(state, command)


def _ollama_shell_reply(state: Dict[str, object], command: str) -> str:
    current_prompt = _prompt(state)
    system = (
        "You are a realistic shell process running on a decoy host. "
        "Output must look exactly like terminal stdout/stderr only. "
        "Never explain, never narrate, never mention assistant/model/prompt/honeynet. "
        "No markdown, no code fences, no labels like 'Output:' or 'Response:'. "
        "If the command is invalid, return only a shell-style error line. "
        "Keep outputs concise and plausible for the given host state."
    )
    prompt = (
        f"Shell family: {state.get('shell_family')}\n"
        f"Host: {state.get('hostname')}\n"
        f"User: {state.get('username')}\n"
        f"Working directory: {state.get('cwd')}\n"
        f"Prompt: {current_prompt}\n"
        f"Command history tail: {json.dumps(state.get('history', [])[-5:])}\n"
        f"Attacker command: {command}\n"
        "Output:"
    )

    for base_url in _build_ollama_urls():
        try:
            response = requests.post(
                f"{base_url}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "stream": False,
                    "keep_alive": "30m",
                    "system": system,
                    "prompt": prompt,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.85,
                    },
                },
                timeout=OLLAMA_TIMEOUT_SECONDS,
            )
            if response.status_code >= 400:
                continue
            parsed = response.json()
            text = str(parsed.get("response", "")).strip()
            if text:
                return text
        except requests.RequestException:
            continue

    return ""


def _sanitize_ollama_output(text: str) -> list[str]:
    if not text:
        return []

    fenced_block = re.findall(r"```(?:[a-zA-Z0-9_-]+)?\n(.*?)```", text, flags=re.DOTALL)
    if fenced_block:
        text = "\n".join(fenced_block)

    cleaned_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("```"):
            continue
        if line.lower().startswith("response:"):
            line = line.split(":", 1)[1].strip()
        if not line:
            continue
        cleaned_lines.append(line)
    return cleaned_lines


def _looks_like_terminal_output(lines: list[str]) -> bool:
    if not lines:
        return False
    joined = " \n".join(lines).lower()
    forbidden = [
        "attacker's shell script",
        "supplied shell state",
        "should be displayed",
        "additional information",
        "explanations",
        "assistant",
        "model",
        "prompt",
        "as an ai",
        "i cannot",
        "i can",
        "you should",
    ]
    if any(token in joined for token in forbidden):
        return False
    return any(
        line.startswith(("/", "~", "uid=", "Path", "Volume in drive", "Ethernet adapter", "Linux", "Ubuntu", "Microsoft Windows"))
        or "$" in line
        or ">" in line
        for line in lines
    )


def _heuristic_terminal_lines(state: Dict[str, object], command: str) -> list[str]:
    lowered = command.lower()
    cwd = str(state.get("cwd", "/var/www/html"))

    if any(word in lowered for word in ["network", "route", "routes", "netstat", "ip route"]):
        return [
            "default via 10.20.30.1 dev eth0 proto dhcp src 10.20.30.15 metric 100",
            "10.20.30.0/24 dev eth0 proto kernel scope link src 10.20.30.15",
            "172.20.88.0/24 dev tun0 proto kernel scope link src 172.20.88.11",
        ]
    if any(word in lowered for word in ["process", "processes", "ps aux", "tasklist"]):
        return [
            "root         1  0.0  0.2  18532  3140 ?        Ss   08:00   0:01 /sbin/init",
            "ubuntu      42  0.1  1.0  78244 21400 ?        Sl   08:02   0:04 python3 app.py",
            "root        77  0.0  0.5  61240 11024 ?        Ss   08:03   0:00 /usr/bin/ssh -D",
        ]
    if any(word in lowered for word in ["files", "directory", "list", "ls"]):
        return ["app.py  logs/  static/  templates/", "README.md  requirements.txt  .env"]
    if any(word in lowered for word in ["current", "pwd", "where am i", "working directory"]):
        return [cwd]
    first_token = command.strip().split()[0] if command.strip() else "command"
    if str(state.get("shell_family")) == "windows":
        return [f"'{first_token}' is not recognized as an internal or external command,"]
    return [f"bash: {first_token}: command not found"]


def simulate_terminal_response(
    command: Optional[str],
    metadata: Optional[Dict[str, object]] = None,
    event_id: Optional[str] = None,
) -> Dict[str, object]:
    metadata = metadata or {}
    session_key = _session_key(metadata, event_id)
    normalized = _normalize_command(command or "")
    state = _load_state(session_key, normalized, metadata)

    touch_session(
        session_key,
        trap="ollama_decoy",
        target_domain="IT",
        metadata={
            "client_ip": str(metadata.get("client_ip") or "unknown"),
            "user_agent": str(metadata.get("user_agent") or ""),
            "path": str(metadata.get("path") or ""),
            "method": str(metadata.get("method") or ""),
        },
    )

    if not normalized:
        prompt = _prompt(state)
        transcript = [
            state.get("banner", ""),
            prompt,
        ]
        state["session_key"] = session_key
        state["prompt"] = prompt
        state["transcript"] = transcript
        transcript = [
            state.get("banner", ""),
            prompt,
        ]
        _persist_state(session_key, state, metadata)
        return {
            "session_key": session_key,
            "terminal_profile": state.get("shell_family"),
            "prompt": prompt,
            "output": [],
            "transcript": transcript,
            "ollama_response": "\n".join(transcript),
            "current_directory": state.get("cwd"),
            "last_exit_code": state.get("last_exit_code", 0),
            "command_history_tail": state.get("history", [])[-10:],
            "banner": state.get("banner"),
        }

    state["history"] = list(state.get("history", [])) + [normalized]
    state["history"] = state["history"][-60:]
    state["last_command"] = normalized

    segments = _split_pipeline(normalized)
    combined_output: List[str] = []
    exit_code = 0
    if _should_use_llm_fallback(normalized, state):
        llm_output = _ollama_shell_reply(state, normalized)
        combined_output = _sanitize_ollama_output(llm_output)
        if not _looks_like_terminal_output(combined_output):
            combined_output = _heuristic_terminal_lines(state, normalized)
        if not combined_output:
            combined_output = [""]
    else:
        for segment in segments:
            shell_output, exit_code = _deterministic_shell_reply(state, segment)
            if shell_output:
                combined_output.extend(shell_output)
            if exit_code != 0:
                break

    if not combined_output and exit_code == 0:
        llm_output = _ollama_shell_reply(state, normalized)
        combined_output = _sanitize_ollama_output(llm_output)
        if not _looks_like_terminal_output(combined_output):
            combined_output = _heuristic_terminal_lines(state, normalized)
        if not combined_output:
            combined_output = [""]

    state["last_exit_code"] = exit_code
    if state.get("shell_family") not in {"linux", "windows"}:
        state["shell_family"] = "linux"

    prompt = _prompt(state)
    transcript = [
        state.get("banner", ""),
        f"{prompt} {normalized}".rstrip(),
        *combined_output,
        prompt,
    ]
    state["last_output"] = "\n".join(combined_output).strip()
    state["session_key"] = session_key
    state["prompt"] = prompt
    state["transcript"] = transcript

    _persist_state(session_key, state, metadata)

    return {
        "session_key": session_key,
        "terminal_profile": state.get("shell_family"),
        "prompt": prompt,
        "output": combined_output,
        "transcript": transcript,
        "ollama_response": "\n".join(transcript),
        "current_directory": state.get("cwd"),
        "last_exit_code": exit_code,
        "command_history_tail": state.get("history", [])[-10:],
        "banner": state.get("banner"),
    }