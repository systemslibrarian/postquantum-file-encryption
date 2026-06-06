# Discoverability

A pre-flight checklist and a list of places to file PRs / posts so the right people find
the library. None of this is automated — adoption follows attention, and attention follows
deliberate, low-volume placement.

The companion [ANNOUNCE.md](ANNOUNCE.md) is a draft post you can publish anywhere; the
entries below cite *where* to publish it and the awesome-* lists worth submitting to.

## Pre-flight (before any submission)

Check that a first-time visitor lands well:

- [ ] The README badges all render and link to live status.
- [ ] The latest published `1.0.0+` release is on nuget.org (both core and Hybrid).
- [ ] The repository has **Discussions** enabled (Settings → General → Features).
- [ ] [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) reflects current reality.
- [ ] At least one example from the README round-trips locally with the published package.
- [ ] [`SECURITY.md`](../SECURITY.md) reporting channels are correct (private advisory + email).

## Awesome-list submissions (open a PR with a 1-line entry)

For each list, the entry should be a single Markdown bullet, kept short. Drop the line into
the most specific section the list offers (cryptography → encryption → post-quantum, in
that order of preference).

Suggested 1-line entry (tune per list):

```markdown
- [PostQuantum.FileEncryption](https://github.com/systemslibrarian/postquantum-file-encryption) — Fail-closed file/stream encryption for .NET 10 with AES-256-GCM, PBKDF2/Argon2id, and a hybrid X25519+ML-KEM-768 recipient mode. Frozen `.pqfe` v2 format, CycloneDX SBOMs, SLSA-style attestations, reproducible builds.
```

Lists worth filing PRs against (verify each URL before submitting — these things move):

| List | URL | Section to target |
| --- | --- | --- |
| awesome-dotnet | https://github.com/quozd/awesome-dotnet | Cryptography |
| awesome-dotnet-core | https://github.com/thangchung/awesome-dotnet-core | Cryptography / Security |
| awesome-cryptography | https://github.com/sobolevn/awesome-cryptography | .NET (or "Tools / Encryption") |
| awesome-security | https://github.com/sbilly/awesome-security | Tools — Encryption |
| awesome-post-quantum | https://github.com/awesomestuff/awesome-post-quantum | Implementations |
| awesome-cryptography-rust | https://github.com/rust-cc/awesome-cryptography-rust | Encryption — for the Rust → WASM reference at `samples/pqfe-wasm` |

Etiquette: one list per PR, follow the list's CONTRIBUTING file if present, never bulk-PR
multiple lists at once. Maintainers notice patterns.

## Long-form announcement venues

The `1.0` post in [ANNOUNCE.md](ANNOUNCE.md) is structured to drop straight into:

- **dev.to** — tag with `dotnet`, `csharp`, `security`, `cryptography`, `postquantum`.
- **Hashnode** — same tags; cross-posts cleanly from dev.to.
- **Microsoft Learn — Community / Tech Community** — `.NET` blog or the security category.
- A **personal blog**; canonical-URL the dev.to crosspost to it.

Don't post the same article to multiple aggregators on the same day; stagger by 1–2 days
so each lands in its own news cycle.

## Aggregators (post once, well)

- **lobste.rs** — needs an invite. If you have one, tag `dotnet` + `cryptography`.
- **Hacker News** — submit as a Show HN: `Show HN: PostQuantum.FileEncryption — fail-closed file encryption for .NET`. Pick a weekday morning US Pacific time. Be present for the first hour to answer questions.
- **Lemmy / Mastodon (`#dotnet`, `#cryptography`)** — short post pointing at the announce.
- **daily.dev** — auto-picks up RSS from dev.to / Hashnode if you set it up.

## Subreddits (read the rules first)

| Subreddit | Notes |
| --- | --- |
| /r/dotnet | High-quality, low-spam. A "I shipped this" post lands well; lead with the *why*, not the install command. |
| /r/csharp | Similar bar to /r/dotnet. |
| /r/cryptography | Read-only for self-promotion in most weeks. If you post, frame it as a request for review of the threat model and format, not as a launch. |
| /r/programming | Hit-or-miss; prefer a long-form blog crosspost to a bare repo link. |

Avoid `/r/netsec` for self-promotion — it has explicit rules against it. After the audit
lands, the *audit report* is on-topic there.

## .NET-specific channels

- **The .NET Foundation directory** — only if you intend to apply for membership. Different
  bar, different commitment.
- **.NET Weekly / .NET News** newsletters — most accept a polite tip via email or a form.
- **The C# Discord** `#showcase` channel — one post, link the announce, answer questions.

## Maintaining momentum

- Pin the latest release to the repo (GitHub → Releases → Latest).
- Open a **Discussion** thread titled "1.0 feedback / show-and-tell" and link it from the
  README's "Getting help" line.
- When the audit lands (or a notable user adopts), write a *second* short post —
  "PostQuantum.FileEncryption 1.x after X audit / X adopters." Audits and case studies
  carry farther than launches.

---

*To God be the glory — 1 Corinthians 10:31.*
