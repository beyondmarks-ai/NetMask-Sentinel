# Publishing NetMask Sentinel to GitHub

The original local repository contains legacy commit authors and an old remote. Source files have been sanitized, but Git commit history cannot be anonymized by editing files.

To publish without the legacy contributors or remote, create a clean export:

```powershell
.\tools\Export-CleanRepository.ps1
cd .\github-release\NetMask-Sentinel
```

The export script copies tracked and publishable untracked source files, excludes runtime logs and ignored build artifacts, initializes a new `main` branch, and creates one generic `NetMask Sentinel` initial commit. It does not configure or contact a remote service.

Create an empty GitHub repository without a generated README, license, or `.gitignore`, then connect the clean export:

```powershell
git remote add origin https://github.com/YOUR-ACCOUNT/netmask-sentinel.git
git push -u origin main
```

Recommended GitHub settings:

1. Enable private vulnerability reporting under **Settings > Code security and analysis**.
2. Enable Dependabot alerts and security updates.
3. Require the `CI / test` check before merging to `main`.
4. Protect `main` from force pushes and deletion.
5. Require pull requests and at least one review where practical.
6. Restrict Actions permissions to read repository contents by default.
7. Publish standalone tester ZIPs as workflow artifacts or release assets, not normal source commits.
8. Never upload Firebase credentials, `.env` files, runtime CSVs, PCAPs, or production logs.

If you intentionally retain the original Git history, GitHub will continue to display its historical authors. A new clean repository is required to remove those historical contributor identities from the public project.