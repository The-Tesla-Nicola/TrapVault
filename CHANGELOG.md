# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CSRF middleware for enhanced security
- Password validators for Django authentication
- CONTRIBUTING.md
- LICENSE (MIT)

### Fixed
- Security configuration in .env (ALLOWED_HOSTS, thresholds)
- DEBUG setting now properly enforced
- SIEM_BLOCK_THRESHOLD corrected to 120

### Changed
- JWT secrets now require 32+ character hex strings

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Django backend with SIEM engine
- React frontend (fintech honeypot UI)
- ML-based anomaly detection (Isolation Forest)
- Real-time threat intelligence enrichment (AbuseIPDB, GeoIP)
- SOAR automation for auto-blocking attackers
- Dual-environment architecture (real bank vs honeypot)
- Prometheus monitoring
- Grafana dashboards
- Docker Compose deployment
