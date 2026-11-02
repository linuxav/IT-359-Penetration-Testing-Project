# Shadow AI Vulnerability Scanner — Internal Module

IT-359 project module. This scanner inventories local AI model files, known application directories, and running processes, and inspects **AI-specific** configuration files for potential credential assignments and insecure settings. It generates a structured JSON report for the group's AI reporting component.

**Scope:** Local host inspection only. The network scanner and attack-testing components belong to teammates. **Run only on your own computer or systems you are authorized to audit.** This is read-only and does not transmit findings.

## Requirements

- Python 3.10+; standard library only (no `pip install` needed)
- Linux recommended for final demonstration; macOS supported for development
- Access to folders being scanned (no need to run as root for basic operation)

## Run

```bash
python3 internal_scan.py --path ~/Downloads --output internal_results.json
python3 -m json.tool internal_results.json
```

For a broader scan of your own home directory:

```bash
python3 internal_scan.py --path ~ --max-files 100000
```

Repeated `--path` arguments allow several authorized directories. By default it scans the home directory. The CLI bounds traversal using `--max-files`, skips common development/cache folders, doesn't follow symlink directories, and logs permission/access errors rather than printing file contents.

## JSON contract

Top-level fields: `schema_version`, `scanner`, `timestamp_utc`, `host`, `scan_roots`, `model_files`, `ai_processes`, `ai_directories`, `config_files`, `findings`, `errors`, `summary`.

Each `findings[]` item contains `type`, `severity`, `description`, and optionally `path`, `evidence`. Severities: `info`, `low`, `medium`, `high`. Model/process/directory detection is informational, **not** proof of a vulnerability. Security findings are heuristics that require manual confirmation.

No API key values or password values are copied into reports. Only candidate **variable names**, setting indicators, and metadata are included. Configuration filenames are inspected only when under recognized AI paths. The JSON report is written with owner-only permissions (`0600`). Do **not** publish real `internal_results.json` files from company or personal systems to GitHub.

## Test

```bash
python3 -m unittest discover -s tests -v
```

To create a harmless test AI file on Linux/macOS:

```bash
mkdir -p /tmp/shadow-ai-demo/ollama
: > /tmp/shadow-ai-demo/ollama/sample.gguf
printf 'DEMO_API_KEY=training-only-example\nauth_enabled=false\n' > /tmp/shadow-ai-demo/ollama/.env
chmod 644 /tmp/shadow-ai-demo/ollama/.env
python3 internal_scan.py --path /tmp/shadow-ai-demo --output /tmp/shadow-ai-demo-results.json
```

These files are **synthetic test fixtures**, not real AI models or secrets. Clean up the temporary test directory when finished.

## Limitations

- Extensions and process names can produce false positives or miss renamed installations.
- A config setting is not proof that a running service uses that setting; the group's network/attack modules must corroborate it.
- Generic model files outside selected scan roots are missed.
- Only a curated set of AI products, configuration filenames, and setting patterns is recognized.
- System service accounts and permission-restricted paths may be inaccessible to unprivileged users; errors are recorded.
- Configurations embedded in containers, encrypted stores, or proprietary binary formats are not covered.
