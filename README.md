# Ghost

Ghost is a public, open-source, quantum-safe bearer commit-and-reveal system
for any data, with no administrator. Committing returns digits that are the only
authority over the data; GHOST, the coin that runs the chain, is the first type
of data and the first demo.

**This project is experimental.** Nothing here has been audited by an outside
firm, nothing is launched, and everything may change. Do not rely on it for
anything of value.

The scope and design decisions are in
[docs/ghost-outline.md](docs/ghost-outline.md).

## Status

The repository currently holds the outline and the ground rules for
contributing. Code follows in the order set out in the outline.

The first product is the web app in [webapp/](webapp/README.md): Vanish,
Summon and Claim with the save check, on top of the client library, with a
build anyone can repeat and compare. Its design is in
[docs/webapp.md](docs/webapp.md).

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

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Licence

The project's own code is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
