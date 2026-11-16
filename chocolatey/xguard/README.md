# XGuard Chocolatey package

This directory contains the Chocolatey package source for XGuard.
The GitHub Actions workflow updates version, MSI URL, and checksum after a release is published.

## Workflow behavior

- Trigger: GitHub release `published` (non-prerelease).
- Source MSI: Release asset named `XGuard_<version>_x64_en-US.msi`.
- Updated files:
  - `xguard.nuspec` (`<version>`, `<packageSourceUrl>`)
  - `tools/chocolateyinstall.ps1` (`$url`, `checksum`)
- Package build: `choco pack`.
- Package push: `choco push` to `https://push.chocolatey.org/`.

## Required secret

- `CHOCO_API_KEY` in GitHub repo secrets.

## Local testing (Windows)

From this directory:

```
choco pack
choco install xguard --source .
```
