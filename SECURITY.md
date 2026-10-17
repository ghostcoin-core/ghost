# Security policy

Ghost is experimental. Nothing here has been audited by an outside firm and
nothing is launched, but we still want to hear about every security problem,
and we treat reports privately until a fix is ready.

## Reporting a vulnerability

Send reports privately to **[hello@ghostcoin.com](mailto:hello@ghostcoin.com)**,
the project's official address, until a dedicated security address exists.
Please do not open a public issue or pull request for a vulnerability.

A useful report says which file or section is affected, what goes wrong, and
how to reproduce it. We will acknowledge the report, keep you informed while we
work on it, and credit you when the fix is published unless you ask us not to.

## Maintainers

- **Primary maintainer:** GhostcoinHQ
- **Backup maintainer:** to be named by the founder

## What this policy covers

This policy covers this repository's own work:

- the proof statements ([docs/spec/02-proof-statements.md](docs/spec/02-proof-statements.md));
- the specification ([docs/spec](docs/spec)), including the commitment format,
  key derivation, coin rules and consensus rules;
- the benchmarks ([benchmarks](benchmarks)) and their published results.

A flaw in a proof statement or in the specification, such as a way to reveal
data without the digits, to forge or replay a reveal, or to break a stated
security property, is in scope even though no code implementing it has shipped.

## The node

Vulnerabilities in the Ghost node are handled under the security policy of the
separate ghost-node repository, not here. The node's backport log
(`SECURITY-BACKPORTS.md`), its upstream triage routine and its emergency release
procedure are kept in ghost-node. Until that repository is published, send node
reports to the same address above and we will handle them under that policy.
