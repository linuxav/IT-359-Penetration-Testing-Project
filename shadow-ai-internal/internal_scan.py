#!/usr/bin/env python3
"""Read-only local AI inventory/security checks for authorized Linux hosts.

Does not probe ports, send requests, collect secret values, or modify target files.
"""

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MODEL_EXTENSIONS = {".gguf", ".safetensors", ".ckpt", ".pt", ".pth", ".onnx"}
PROCESS_PATTERNS = {
    "Ollama": re.compile(r"(?:^|[/\s])ollama(?:$|[\s-])", re.I),
    "LM Studio": re.compile(r"lm[ -]?studio", re.I),
    "AnythingLLM": re.compile(r"anythingllm", re.I),
    "llama.cpp": re.compile(r"(?:llama-server|llama\.cpp)", re.I),
    "vLLM": re.compile(r"(?:^|[/\s])vllm(?:$|[\s-])", re.I),
    "LocalAI": re.compile(r"(?:^|[/\s])local-ai(?:$|[\s-])", re.I),
    "text-generation-webui": re.compile(r"text-generation-webui", re.I),
}
AI_DIRS = [
    ".ollama", ".cache/huggingface", ".cache/lm-studio", ".lmstudio",
    ".config/LM Studio", ".local/share/LM Studio", "AnythingLLM",
    ".config/anythingllm", ".local/share/anythingllm",
]
SYSTEM_AI_DIRS = ["/opt/ollama", "/opt/anythingllm", "/var/lib/ollama", "/usr/local/share/ollama"]
CONFIG_NAMES = {"config.json", "config.yaml", "config.yml", "settings.json", "settings.yaml", "settings.yml", ".env", "config.toml", "server.yaml", "server.yml"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".Trash", ".cache/pip", "Library", ".npm"}
# Match credential assignments while retaining only variable names in scan results.
SECRET_ASSIGNMENT = re.compile(
    r'(?im)^\s*["\']?([A-Za-z_][A-Za-z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET[_-]?KEY|AUTH[_-]?TOKEN|PASSWORD)[A-Za-z0-9_]*)["\']?\s*[:=]\s*["\']?([^\s"\',#}]+)'
)
PLACEHOLDERS = {"", "none", "null", "false", "changeme", "your_key_here", "example", "placeholder", "not_set", "<redacted>"}
DISABLED_AUTH = re.compile(r'(?im)^\s*["\']?(?:auth_enabled|require_auth|authentication_enabled)["\']?\s*[:=]\s*(?:false|no|0)\b')
BIND_ALL = re.compile(r'(?im)^\s*["\']?(?:host|listen_host|bind_address)["\']?\s*[:=]\s*["\']?0\.0\.0\.0\b')


def finding(kind, severity, path=None, description="", evidence=None):
    item = {"type": kind, "severity": severity, "description": description}
    if path is not None:
        item["path"] = str(path)
    if evidence:
        item["evidence"] = evidence
    return item


def known_directories(home):
    result = [home / name for name in AI_DIRS]
    if platform.system() == "Linux":
        result.extend(Path(x) for x in SYSTEM_AI_DIRS)
    return result


def walk_files(roots, max_files, errors):
    """Bounded, non-following traversal; errors are recorded rather than crashing."""
    seen = set()
    count = 0
    for root in roots:
        root = Path(root).expanduser()
        if not root.exists():
            errors.append(f"Scan path not found: {root}")
            continue
        if root.is_symlink():
            errors.append(f"Symlink scan root skipped: {root}")
            continue
        if root.is_file():
            if root not in seen:
                yield root
                count += 1
            if count >= max_files:
                errors.append(f"File inspection limit reached ({max_files})")
                return
            continue

        def onerror(err):
            errors.append(f"Cannot access directory: {err.filename}: {err.strerror}")

        for base, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(base) / d).is_symlink()]
            for name in files:
                path = Path(base) / name
                if path.is_symlink() or path in seen:
                    continue
                seen.add(path)
                yield path
                count += 1
                if count >= max_files:
                    errors.append(f"File inspection limit reached ({max_files})")
                    return


def inspect_config(path, errors):
    """Return metadata-only findings; no credential values retained or printed."""
    results = []
    try:
        metadata = path.stat()
        if metadata.st_size > 1_000_000:
            errors.append(f"Config exceeds 1 MB limit: {path}")
            return results
        if path.is_symlink():
            return results
        content = path.read_text(encoding="utf-8", errors="replace")
        assignments = []
        for match in SECRET_ASSIGNMENT.finditer(content):
            key, value = match.group(1), match.group(2)
            if value.strip().lower() not in PLACEHOLDERS and not value.startswith("${"):
                assignments.append(key)
        if assignments:
            names = sorted(set(assignments))[:20]
            world_readable = bool(metadata.st_mode & stat.S_IROTH)
            group_readable = bool(metadata.st_mode & stat.S_IRGRP)
            results.append(finding(
                "possible_embedded_secret", "high" if world_readable else "medium",
                path, "Potential credential assignments in AI configuration; manual verification required",
                {"variable_names": names, "other_readable": world_readable,
                 "group_readable": group_readable}
            ))
        if (metadata.st_mode & (stat.S_IRGRP | stat.S_IROTH)) and (path.name == ".env" or assignments):
            results.append(finding("sensitive_config_permissions", "high" if metadata.st_mode & stat.S_IROTH else "medium",
                                    path, "Sensitive configuration readable by group or other users",
                                    {"permissions": oct(stat.S_IMODE(metadata.st_mode))}))
        if DISABLED_AUTH.search(content):
            results.append(finding("authentication_disabled_setting", "high", path,
                                    "Configuration appears to disable authentication; verify effective runtime settings"))
        if BIND_ALL.search(content):
            results.append(finding("all_interfaces_bind_setting", "low", path,
                                    "Configuration specifies a wildcard bind address; verify network exposure and controls"))
    except (OSError, UnicodeError) as exc:
        errors.append(f"Cannot inspect config {path}: {type(exc).__name__}")
    return results


def inspect_processes(errors):
    found = []
    if platform.system() not in {"Linux", "Darwin"}:
        errors.append("Process enumeration is supported on Linux and macOS only")
        return found
    try:
        # Use executable names, not command-line arguments, to avoid exposing secrets.
        output = subprocess.run(["ps", "-eo", "pid=,comm="], capture_output=True,
                                text=True, check=True, timeout=10).stdout
        for line in output.splitlines():
            pieces = line.strip().split(maxsplit=1)
            if len(pieces) != 2 or not pieces[0].isdigit():
                continue
            pid, executable = pieces
            for product, pattern in PROCESS_PATTERNS.items():
                if pattern.search(executable):
                    found.append({"name": product, "pid": int(pid), "executable": Path(executable).name})
                    break
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Process enumeration failed: {type(exc).__name__}")
    return found


def run_scan(roots, max_files=100000, include_processes=True):
    errors = []
    home = Path.home()
    dirs = [str(d) for d in known_directories(home) if d.is_dir()]
    known = [Path(d).resolve() for d in dirs]
    models, configs, findings = [], [], []
    for path in walk_files(roots, max_files, errors):
        suffix = path.suffix.lower()
        if suffix in MODEL_EXTENSIONS:
            models.append(str(path))
            findings.append(finding("model_file", "info", path, "AI model file extension detected (content not validated)"))
        # Restrict config analysis to AI-related paths to reduce unrelated findings.
        if path.name.lower() in CONFIG_NAMES:
            is_known_ai = any(path == parent or parent in path.parents for parent in known)
            if is_known_ai or any("ollama" in part.lower() or "huggingface" in part.lower() or "anythingllm" in part.lower() or "lmstudio" in part.lower() for part in path.parts):
                configs.append(str(path))
                findings.extend(inspect_config(path, errors))
    # Include known AI config locations even when outside selected scan roots.
    config_seen = set(configs)
    for parent in known:
        for name in CONFIG_NAMES:
            path = parent / name
            if path.is_file() and not path.is_symlink() and str(path) not in config_seen:
                configs.append(str(path))
                config_seen.add(str(path))
                findings.extend(inspect_config(path, errors))
    processes = inspect_processes(errors) if include_processes else []
    for proc in processes:
        findings.append(finding("ai_process", "info", description=f"Running {proc['name']} process",
                                evidence={"pid": proc["pid"], "name": proc["name"]}))
    for directory in dirs:
        findings.append(finding("ai_directory", "info", directory, "Known AI application directory present"))
    return {
        "schema_version": "1.0", "scanner": "shadow_ai_internal",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"os": platform.system().lower(), "hostname": platform.node()},
        "scan_roots": [str(Path(p).expanduser()) for p in roots],
        "model_files": models, "ai_processes": processes, "ai_directories": dirs,
        "config_files": configs, "findings": findings,
        "errors": errors, "summary": {"models": len(models), "processes": len(processes),
                                      "directories": len(dirs), "configs": len(configs),
                                      "security_findings": sum(f["severity"] not in {"info"} for f in findings)},
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only local Shadow AI inventory and config audit (Linux/macOS)")
    parser.add_argument("--path", action="append", dest="paths", metavar="DIRECTORY",
                        help="Directory to scan; repeatable. Default: current user's home directory")
    parser.add_argument("--output", default="internal_results.json", help="JSON output path")
    parser.add_argument("--max-files", type=int, default=100000, help="Bound on number of files inspected")
    parser.add_argument("--no-processes", action="store_true", help="Skip process inspection (useful for tests)")
    args = parser.parse_args()
    if args.max_files < 1:
        parser.error("--max-files must be positive")
    roots = args.paths or [str(Path.home())]
    print("Starting Shadow AI Internal Scanner (read-only)...")
    results = run_scan(roots, args.max_files, include_processes=not args.no_processes)
    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Restrict JSON output to owner-only permissions because scan metadata is sensitive.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(output, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
        stream.write("\n")
    print(f"Models: {results['summary']['models']} | Processes: {results['summary']['processes']} | "
          f"AI directories: {results['summary']['directories']} | "
          f"Security findings: {results['summary']['security_findings']}")
    print(f"Saved: {output}")
    if results["errors"]:
        print(f"Warnings: {len(results['errors'])} (see JSON errors field)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
