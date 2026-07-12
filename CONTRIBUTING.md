# Contributing to TrapVault

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/TrapVault.git
cd TrapVault

# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install

# Configure
cp .env.example .env

# Run tests
make test
```

## Code Style

- Python: Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use `black` for formatting: `black .`
- Use `flake8` for linting: `flake8 .`
- JavaScript/TypeScript: Follow project ESLint config

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: fix a bug
docs: update documentation
style: formatting, no code change
refactor: restructure code
test: add/update tests
chore: maintenance
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `make test`
5. Commit: `git commit -am 'feat: add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Submit a Pull Request

## Reporting Issues

Use GitHub Issues to report:
- Bugs with reproduction steps
- Feature requests with use cases
- Security vulnerabilities (do NOT disclose publicly)

## License

By contributing, you agree your code will be licensed under the MIT License.
