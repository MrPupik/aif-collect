# AI-fluent collect

Bundles your Claude Code sessions into one zip

- **Local only.** No network calls, nothing is uploaded. You send the zip yourself.
- **Read only.** Your original files are never modified.

## Run it

You need Python 3.8 or newer. 

### macOS / Linux (Terminal)

```sh
curl -fsSLO https://raw.githubusercontent.com/MrPupik/aif-collect/main/aif_collect.py && python3 aif_collect.py
```

### Windows (PowerShell)

```powershell
curl.exe -fsSLO https://raw.githubusercontent.com/MrPupik/aif-collect/main/aif_collect.py; python aif_collect.py
```

If `python` isn't found, try `py aif_collect.py`, or install Python from https://www.python.org/downloads/ (tick "Add python.exe to PATH").

Notes:
- **macOS:** if `python3` is missing, macOS offers to install the developer tools; accept, or install Python from python.org.
- **Windows:** use PowerShell, not the old Command Prompt, for the best arrow-key menu. In plain `cmd`, use `curl -fsSLO ...` then `python aif_collect.py`.
- **WSL:** run it inside WSL to export WSL sessions. Sessions from Windows itself live in the Windows user folder, so run it in PowerShell for those.

## What happens

1. Pick projects
2. Optionally enter names to anonymize
3. A review screen shows what will be included,
4. You get `aif-export-YYYYMMDD-HHMM.zip` on your Desktop (or home folder). Send it yourself.

If you use step (2). Secrets become `[REDACTED]`, your home path and username become `<USER>`. `.env`, key files, `node_modules` and files over 5 MB are left out. 

## Options

| Flag | Meaning |
| --- | --- |
| `--dry-run` | print exactly which files would be zipped, write nothing |
| `--since YYYY-MM-DD` | only sessions modified on or after this date |
| `--no-git` | leave out git history |
| `--out <folder or .zip>` | where to write the zip (default: Desktop) |
| `--claude-dir <folder>` | your Claude data folder, if it isn't found automatically |

If nothing is found, the tool prints the folders it checked. By default it looks in `$CLAUDE_CONFIG_DIR`, `~/.claude` and `~/.config/claude`.

## Development

```sh
python3 -m unittest discover tests
```

Tested on Linux (WSL). macOS and Windows are expected to work but have had less testing.
