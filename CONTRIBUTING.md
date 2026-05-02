# Contributing

Thanks for taking the time to improve AI Proxy.

## Ground Rules

- Keep changes focused. One fix or feature per pull request is easiest to review.
- Do not include real API keys, auth tokens, prompts, logs with secrets, or captured traffic.
- Add or update tests when behavior changes.
- Update documentation when configuration, security behavior, or user-facing commands change.
- Follow the existing Rust style and run the standard checks before opening a pull request.

## Development Setup

```bash
git clone https://github.com/lee-to/ai-proxy.git
cd ai-proxy
cp config.example.toml config.toml
cargo build
```

## Checks

Run these before submitting:

```bash
cargo fmt --check
cargo check
cargo test
```

The Makefile also provides:

```bash
make check
make test
```

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Make the smallest practical change.
3. Include tests or explain why tests are not practical.
4. Update docs for config, security, or workflow changes.
5. Open a pull request with a clear description and verification notes.

## Reporting Bugs

Use GitHub Issues for regular bugs. For security-sensitive reports, do not open a public issue; follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the MIT License.
