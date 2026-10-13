# Ghost

Ghost is a public, open-source commit and reveal system for data, with no
privileged protocol administrator. GHOST is the coin that runs the chain.

**This project is experimental.** Nothing here has been audited by an outside
firm, nothing is launched, and everything may change. Do not rely on it for
anything of value.

The scope and design decisions are in
[docs/ghost-outline.md](docs/ghost-outline.md).

## Status

The repository currently holds the outline and the ground rules for
contributing. Code follows in the order set out in the outline.

## Contributing

After cloning, turn on the local commit message check with one command:

```sh
git config core.hooksPath .githooks
```

Commit messages must be written as the project's own. A message is rejected,
locally and in CI, if it names an AI tool or vendor, carries a
`Co-authored-by:` trailer, or carries a "Generated with" line. The exact rules
are in [scripts/check-commit-message.sh](scripts/check-commit-message.sh).

All changes to `main` go through a pull request, and the CI jobs must pass.

## Licence

The project's own code is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
