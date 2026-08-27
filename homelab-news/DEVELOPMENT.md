# Development guide

Homelab News follows modern Python conventions while adopting the transferable
parts of the GNU Coding Standards: conventional interfaces, descriptive names,
explicit error handling, documented contracts, and modules organized around one
purpose.

## Source boundaries

- `homelab_news/` is the portable application package. New reusable code belongs
  here, organized behind collector, newsroom, configuration, and capability
  contracts. Top-level modules are worker entry points or compatibility facades.
- `homelab_news/configuration.py` owns typed feature policy loaded from TOML and
  environment overrides. Connection secrets remain environment-only.
- `homelab_news/collectors/` owns collector contracts and source-specific raw
  retrieval. Collectors return events plus explicit completeness metadata.
- `homelab_news/newsroom/` owns deterministic selection and mandatory coverage.
- `config.py` owns environment parsing and derived paths. Import configuration
  from here rather than reading the environment throughout the application.
- `storage.py` owns durable JSON reads and atomic writes.
- `articles.py` is the trust boundary for untrusted LLM article output.
- `runtime.py` owns scheduling behavior shared by long-running workers.
- `correlations.py` owns the operational event ledger: normalization, retention,
  and same-service correlation.
- `search.py` owns the archived-article full-text index (SQLite FTS5).
- `lib.py` remains a compatibility facade for integrations, inference, security,
  and rendering while those areas are extracted incrementally. New foundational
  code must not be added to it.
- Worker files contain orchestration, not reusable implementation.

Imports should flow from workers and the web application toward focused modules.
Foundational modules must not import workers or `lib.py`.

## Coding conventions

- Use descriptive `snake_case` names and reserve uppercase names for constants.
- Give each module a short statement of purpose.
- Document public functions in terms of behavior, inputs, results, and important
  failure behavior. Do not restate obvious syntax.
- Catch the narrowest practical exception. Include the failing resource and the
  underlying error in operational logs.
- Express deliberate limits as named policy values and test their boundaries.
- Preserve persisted JSON compatibility unless a migration is included.
- Keep worker entry points and `--help` behavior stable for operators.

## Validation

Run syntax and whitespace checks on the host:

```sh
python3 -m py_compile homelab-news/*.py homelab-news/tests/*.py
git diff --check
```

Run the complete suite in the application image so it uses production
dependencies:

```sh
docker build -t homelab-news-test homelab-news
docker run --rm \
  -v "$PWD/homelab-news/tests:/app/tests:ro" \
  homelab-news-test \
  python -m unittest discover -s /app/tests -p 'test_*.py' -v
```

Before deployment, also validate the Compose model with `./dc.sh config --quiet`.
