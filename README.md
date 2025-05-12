# Common Python Library for GitHub Actions

[![Version](https://img.shields.io/github/v/release/edenlabllc/github_actions.common?style=for-the-badge)](https://github.com/edenlabllc/github_actions.common/releases/latest)
[![License](https://img.shields.io/github/license/edenlabllc/github_actions.common?style=for-the-badge)](LICENSE)
[![Powered by Edenlab](https://img.shields.io/badge/powered%20by-Edenlab%20LLC-8A2BE2.svg?style=for-the-badge)](https://edenlab.io)

Reusable Python library of helpers and utilities used across Edenlab LLC's GitHub Actions (CI, CD, Tenant workflows).  
Published as an open-source package for internal and public consumption.

## What it does

This package centralizes shared logic used by all GitHub Actions developed by Edenlab LLC.  
It is not intended for standalone use, but rather as a dependency in  GitHub Actions.

**Key features:**

- Artifact tagging and release automation
- Slack notification helpers
- Environment selectors and input parsers
- AWS/GCP/Azure credential utilities
- GitHub environment context resolver
- ECR scan results & error handling
- RMK compatibility layer

## Requirements

- Python 3.10 or higher
- GitHub Actions using `composite` workflows

## Directory structure

Source code is located under [`src/github_actions/`](./src/github_actions).

## GitHub package usage

To install from `requirements.txt`, no authentication required:

```text
git+https://github.com/edenlabllc/github_actions.common.git@v1#egg=github_actions.common
```

See [`examples/`](./examples) for more requirements files.

## Used by

This package is used by the following Edenlab LLC's GitHub Actions:

- [`gitlabflow.cd.action`](https://github.com/edenlabllc/gitlabflow.cd.action) — GitLabFlow-style CD with RMK and multi-cloud support  
- [`tenant.artifact.ci.action`](https://github.com/edenlabllc/tenant.artifact.ci.action) — Artifact tagging and release propagation
- other internal Edenlab LLC's repositories and private automation tools

## Internals

- [`pyproject.toml`](./pyproject.toml) — project metadata and dependency definitions  
- [`src/github_actions/`](./src/github_actions) — core library source code  
- [`examples/`](./examples) — example ready-to-use requirements files.
