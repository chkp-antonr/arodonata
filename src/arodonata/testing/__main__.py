"""CLI entrypoint for `python -m arodonata.testing` (delegates to `arodonata.testing.mock_server`)."""

from arodonata.testing.mock_server import main

if __name__ == "__main__":
    raise SystemExit(main())
