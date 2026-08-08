# Contributing

Contributions are welcome for defensive network analysis, parser hardening, tests, detections, documentation and UI improvements.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
ruff check packetscope tests scripts
```

## Parser changes

Add tests for valid, truncated and malformed inputs. Keep parsing bounded; never execute capture-derived content or automatically contact capture-derived network indicators.

## Detection changes

A detection should include clear analyst-facing rationale, evidence fields, confidence, a recommendation, false-positive context in documentation where appropriate, and deterministic tests.
