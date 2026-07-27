# Contributing

Thank you for improving NetMask Sentinel.

## Before opening a change

- Use the project only for defensive and authorized purposes.
- Open a focused issue for significant behavior or architecture changes.
- Do not include credentials, private packet captures, personal data, generated logs, model training data without redistribution rights, or compiled artifacts.
- Report security vulnerabilities privately according to `SECURITY.md`.

## Development setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

## Required checks

```powershell
$env:CAPTURE_ENABLED = 'false'
python -m unittest discover -v
python evaluate_model.py --smoke
python -m compileall -q application.py netmask flow tests
node --check static\js\application.js
```

Add tests for bug fixes and new behavior. Keep capture, feature extraction, inference, and HTTP concerns separated. Do not change the canonical 39-feature order without a versioned model migration and representative labeled evaluation.

## Pull requests

A pull request should explain the problem, implementation, verification performed, security/privacy impact, and any configuration or model compatibility changes. Keep generated `runtime/`, `reports/`, `build/`, `dist/`, `.venv/`, ZIP, EXE, and shortcut files out of commits.