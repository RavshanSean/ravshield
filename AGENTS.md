# RavShield

RavShield is a pure-Python defensive-cybersecurity library (no server, CLI, database, or required network I/O). It exposes threat-analysis functionality as importable classes: analyzers + a `ScanPipeline` that combine findings into an `AnalysisResult` (verdict, severity, risk score, confidence, findings).

## Cursor Cloud specific instructions

- This is a `src/`-layout package (`ravshield` under `src/`) with only `pytest` as a dev dependency. The startup update script installs it editable via `pip install -e ".[dev]" --break-system-packages` (the system Python is externally managed, hence the flag). There are no services to start, no ports, and no environment variables/secrets.
- Console scripts land in `~/.local/bin`, which is not on `PATH`. Invoke tooling as modules instead: run tests with `python3 -m pytest` and build with `python3 -m build` (rather than bare `pytest` / `pyproject-build`).
- There is no linter/formatter/type-checker configured (no ruff/flake8/black/mypy/pre-commit) and no CI. "Lint" is effectively not applicable; verification = the pytest suite.
- `src/ravshield.egg-info/` is committed even though `.gitignore` excludes `*.egg-info/`. An editable install rewrites `SOURCES.txt`; revert that incidental change (`git checkout -- src/ravshield.egg-info/SOURCES.txt`) before committing so it doesn't pollute diffs.
- Verdict policy (v0.2+): heuristics/behavior alone cap at `SUSPICIOUS`. `MALICIOUS` requires confirmed intel (`ioc_match`, `*_REPUTATION_MALICIOUS`, hash IOC, or enrichment malicious tags).
- Ready factories: `create_url_pipeline`, `create_domain_pipeline`, `create_email_pipeline`, `create_ip_pipeline`, `create_file_pipeline`, `create_hash_pipeline`. Optional `ioc_store=` wires IOC matching into URL/domain/email/IP pipelines. Email pipeline includes offline SPF/DKIM/DMARC header analysis (`EmailAuthAnalyzer`).
- Enrichment (DNS/WHOIS/ASN/etc.) is opt-in via `ravshield.plugins.enrichment` (`Enricher` protocol / `StaticMapEnricher`); core remains offline.
- Quick end-to-end smoke check of the core engine:
  `python3 -c "from ravshield.analyzers import create_url_pipeline; r=create_url_pipeline().scan('https://user:pass@login.verify.account.example.com/%76erify'); print(r.verdict, r.severity, [f.code for f in r.findings])"`
