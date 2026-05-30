<!-- Thanks for contributing! For security vulnerabilities, do NOT open a PR — see SECURITY.md. -->

## What & why

<!-- A short description of the change and the motivation. Link the issue it addresses. -->

## Checklist

- [ ] Builds clean (`dotnet build -c Release`, warnings are errors)
- [ ] Tests pass (`dotnet test -c Release`) and I added/extended tests for this change
- [ ] If I touched the container format: updated `docs/FILE-FORMAT.md`, bumped `FormatVersion`,
      added/updated a known-answer vector, and kept the .NET ↔ Rust cross-check green
- [ ] If I touched cryptography: no homegrown primitives; fail-closed behavior preserved
- [ ] If I added a limitation: recorded it in `KNOWN-GAPS.md`
- [ ] Updated `CHANGELOG.md` under `[Unreleased]`

## Security impact

<!-- Does this change affect the threat model, key handling, or the on-disk format? Be explicit. -->
