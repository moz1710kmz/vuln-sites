"""Small .env loader for local, dependency-free startup paths."""

import os


def _strip_quotes(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def load_env_file(base_dir):
    """Load KEY=VALUE lines from .env without overriding existing environment."""
    path = os.path.join(base_dir, ".env")
    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key or key.startswith("#") or key in os.environ:
                continue
            os.environ[key] = _strip_quotes(value.strip())
