# contributing

## local checks

```bash
python -m pip install -e . pytest
pytest -q
python -m black_ice.cli analyze examples/report.json
```

## review checklist

- does the change stay defensive and non-executing?
- are indicators and scores explainable?
- does the change avoid secrets and personal data?
- are response actions approval-gated?
- are tests included for new behavior?
- are operational limits and failure paths documented?

## reporting a security issue

do not upload real malware, credentials, private reports, or personal data to a public issue. report sensitive issues privately to the repository owner and include only the minimum safe reproduction details.
