# Security Policy

## Supported Use

This open-source edition is intended for self-hosted deployments. Operators are responsible for deployment hardening, access control, network exposure, data retention, backups, and provider configuration.

## Reporting Vulnerabilities

Please report vulnerabilities through a private security advisory in the GitHub repository, or by contacting the repository maintainers privately. Do not disclose exploitable details in public issues until a fix or mitigation is available.

Useful reports include:

- Affected version or commit
- Reproduction steps
- Expected and actual behavior
- Impact assessment
- Logs or screenshots with secrets removed

## Secret Handling

Never commit `.env` files, provider keys, private keys, customer documents, scanner outputs from real systems, or production exports. The checked-in `.env.example` files contain development placeholders only.

If a secret is committed by mistake:

1. Revoke or rotate it immediately.
2. Remove it from the public tree.
3. Rewrite repository history before publishing if the secret is present in any commit.

## Production Checklist

Before exposing ThreatGenix beyond localhost:

- Set `APP_ENV=production`.
- Set a generated `SECRET_KEY` with at least 32 characters.
- Use TLS at the edge.
- Use a managed PostgreSQL database with backups.
- Restrict `ALLOWED_ORIGINS` to HTTPS browser origins.
- Set `TRUSTED_HOSTS` to the public API host.
- Decide whether AI provider data transfer is allowed.
- Keep `ALLOW_EXTERNAL_AI_PROVIDERS_IN_PRODUCTION=false` unless users have explicitly opted in.
- Keep live validation runner paths scoped with `THREATGENIX_VALIDATION_ALLOWED_PATHS`.
- Run scanners in isolated worker infrastructure, not on the public API host.
- Run `scripts/check-oss-hygiene.sh` before public releases.
