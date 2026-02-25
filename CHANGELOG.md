# Changelog

## 1.0.0 — 2026-02-25
- Initial public release
- Switched GeoIP lookups to HTTPS with optional `SENTINEL_GEO_LOOKUP` flag and documented the single outbound call
- Reduced information disclosure by truncating executable paths and removing usernames from API responses
- Added host binding warning for non-local addresses
- Upgraded Flask, Werkzeug, and psutil to current stable versions and refreshed dependency audit (pip-audit)
