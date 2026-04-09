# Contributing

## Local setup

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -e .[dev]
```

If you prefer a different Python version, use any interpreter supported by the package metadata.

## Run checks

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

Build the source and wheel distributions:

```bash
uv build
```

If you are working in a restricted environment that already has `setuptools` and `wheel`
available, `uv build --no-build-isolation` is a reasonable fallback.

## Before opening a pull request

- Keep behavior-preserving refactors separate from documentation-only changes when possible.
- Update the README when you change the external login contract or the supported configuration.
- Add or update tests for any authentication flow change.
- Include the commands you used for verification in the pull request description.
