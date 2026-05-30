# OSS-Fuzz integration

These files integrate the Rust `.pqfe` parser fuzz target with
[OSS-Fuzz](https://github.com/google/oss-fuzz), Google's continuous fuzzing service.

- `project.yaml` — project metadata (language, repo, engines, sanitizers).
- `Dockerfile` — clones the repo into the OSS-Fuzz Rust base image.
- `build.sh` — builds the fuzz target with `cargo fuzz build` and stages `decrypt` in `$OUT`.

## Submitting

1. Fork [google/oss-fuzz](https://github.com/google/oss-fuzz).
2. Copy these three files to `projects/postquantum-file-encryption/`.
3. Open a PR. Acceptance and the ongoing fuzzing run are managed by the OSS-Fuzz maintainers.

## Test the build locally (optional)

With the OSS-Fuzz repo checked out:

```bash
python infra/helper.py build_image postquantum-file-encryption
python infra/helper.py build_fuzzers postquantum-file-encryption
python infra/helper.py run_fuzzer postquantum-file-encryption decrypt
```

Until onboarding, the same target runs in this repo's nightly
[`fuzz` workflow](../.github/workflows/fuzz.yml) — see [docs/FUZZING.md](../docs/FUZZING.md).
