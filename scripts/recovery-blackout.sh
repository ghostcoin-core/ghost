#!/usr/bin/env bash
# Recovery with every project-run service blocked: proves that a holder who
# has only a key's digits can restore it and spend it with an independent
# node built from the published source and a wallet they built themselves,
# with no project-run website, endpoint, indexer or download location
# reachable. docs/recovery-test.md explains what it shows and what it cannot.
#
#   1. Build, before anything is blocked: ghost-node from its published
#      source at the commit in webapp/test/e2e/NODE_COMMIT, twice in two
#      directories, and the two binaries must be byte for byte the same; and
#      the wallet with webapp/build.sh, whose SHA256SUMS must check.
#   2. Block: a network namespace of its own whose only way out is a dummy
#      interface behind an nftables table that rejects and counts every
#      packet not on loopback, with one counter for the addresses of the
#      project-run hosts (resolved before the namespace is made) and one for
#      all other egress. DNS inside the namespace points into that rule too.
#      A self-check proves the rule counts a connection to a project-run
#      address; then every project-run host is probed by name and by address
#      from inside, and the run fails if any answers.
#   3. Run webapp/test/e2e/recovery.test.mjs inside the namespace, as the
#      calling user: three nodes of the internal network, an independent node
#      synced from peers only, and a clean device that restores from digits
#      alone and spends (see the test's header for the cases).
#   4. Fail if either counter moved during the run (a project-run host was
#      used, or anything tried to leave the internal network), if any case
#      failed or did not run, or, with --require-all, if any case was
#      skipped. Skipped cases are printed with their reason; a skip is never
#      a pass.
#   5. Tear down: stop what is left in the namespace, delete it and its
#      resolv.conf, and remove the work directory. No rule outside the
#      namespace is touched.
#
# It needs git, Go, a C compiler, Node.js, rustup with the toolchain of
# webapp/build.sh, nft, ip, setpriv and sudo (for the namespace only; the
# builds and the test run as the calling user).
#
# Environment:
#   GHOST_NODE_REPO          the node's published source (default: the public
#                            ghost-node repository); any mirror of it works
#   GHOST_RECOVERY_HOSTS     more project-run host names to block and probe,
#                            separated by spaces
#   GHOST_RECOVERY_WORK      the work directory (default: a new one under TMPDIR)
#   GHOST_RECOVERY_KEEP=1    keep the work directory
#
# Usage: scripts/recovery-blackout.sh [--require-all]
#   --require-all   fail if any case is skipped (the launch gate runs this)
set -euo pipefail

require_all=0
for arg in "$@"; do
  if [ "$arg" = "--require-all" ]; then
    require_all=1
  elif [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 0
  else
    echo "recovery-blackout: unknown argument $arg" >&2
    exit 2
  fi
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
webapp="$repo/webapp"
node_repo="${GHOST_NODE_REPO:-https://github.com/ghostcoin-core/ghost-node.git}"

# The hosts the project runs, or that hold its source and releases: its
# website, its organisation's code and release downloads, and its container
# registry. None of them may be needed to recover a coin.
project_hosts=(
  ghostcoin.com www.ghostcoin.com
  github.com api.github.com codeload.github.com objects.githubusercontent.com
  raw.githubusercontent.com release-assets.githubusercontent.com ghcr.io
)
read -r -a extra_hosts <<<"${GHOST_RECOVERY_HOSTS:-}"
project_hosts+=("${extra_hosts[@]}")

die() {
  echo "recovery-blackout: FAIL: $*" >&2
  exit 1
}
say() { echo "recovery-blackout: $*" >&2; }

[ "$(id -u)" -ne 0 ] || die "run it as an ordinary user; it asks sudo only for the namespace"
for tool in git go node nft ip setpriv sudo sha256sum getent rustup timeout; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done
sudo -n true 2>/dev/null || say "sudo will ask for a password for the namespace"

work="${GHOST_RECOVERY_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ghost-recovery.XXXXXX")}"
mkdir -p "$work"
ns="ghost-rt-$$"
ns_made=0
netns_dir_made=0
uid="$(id -u)"
gid="$(id -g)"

teardown() {
  local status=$?
  if [ "$ns_made" = 1 ]; then
    # Anything still running in the namespace, then the namespace itself.
    local pids
    pids="$(sudo ip netns pids "$ns" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      # shellcheck disable=SC2086
      sudo kill -TERM $pids 2>/dev/null || true
      sleep 2
      # shellcheck disable=SC2086
      sudo kill -KILL $pids 2>/dev/null || true
    fi
    sudo ip netns del "$ns" 2>/dev/null || true
    sudo rm -rf "/etc/netns/$ns"
    if [ "$netns_dir_made" = 1 ]; then sudo rmdir /etc/netns 2>/dev/null || true; fi
    if ip netns list 2>/dev/null | grep -qw "$ns"; then
      echo "recovery-blackout: WARNING: namespace $ns is still there" >&2
    else
      say "namespace $ns removed"
    fi
  fi
  if [ "${GHOST_RECOVERY_KEEP:-0}" = 1 ]; then
    say "work directory kept: $work"
  else
    rm -rf "$work"
  fi
  exit "$status"
}
trap teardown EXIT
trap 'exit 130' INT TERM

# --- 1. Build from the published source, before the blackout ---

say "building ghost-node from $node_repo, twice"
geth_a="$(GHOST_NODE_REPO="$node_repo" GHOST_NODE_DIR="$work/node-a" "$webapp/scripts/build-node.sh")"
geth_b="$(GHOST_NODE_REPO="$node_repo" GHOST_NODE_DIR="$work/node-b" "$webapp/scripts/build-node.sh")"
sum_a="$(sha256sum "$geth_a" | cut -d' ' -f1)"
sum_b="$(sha256sum "$geth_b" | cut -d' ' -f1)"
[ "$sum_a" = "$sum_b" ] || die "the two builds of ghost-node differ ($sum_a, $sum_b): the build is not reproducible"
say "ghost-node $(tr -d '[:space:]' <"$webapp/test/e2e/NODE_COMMIT") built twice, identical: sha256 $sum_a"

say "building the wallet with webapp/build.sh"
"$webapp/build.sh" >&2
(cd "$webapp/dist" && sha256sum --quiet -c SHA256SUMS) || die "webapp/dist does not match its SHA256SUMS"
wasm="$webapp/dist/ghost_webapp_wasm.wasm"
say "wallet built: sha256 $(sha256sum "$wasm" | cut -d' ' -f1) ghost_webapp_wasm.wasm"

# --- 2. The blackout ---

# The project-run hosts' addresses, resolved now, while they still resolve.
v4=()
v6=()
for h in "${project_hosts[@]}"; do
  while read -r addr; do
    if [ -z "$addr" ]; then
      continue
    elif [[ "$addr" == *:* ]]; then
      v6+=("$addr")
    else
      v4+=("$addr")
    fi
  done < <(getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u)
done
if [ "${#v4[@]}" -gt 0 ]; then mapfile -t v4 < <(printf '%s\n' "${v4[@]}" | sort -u); fi
if [ "${#v6[@]}" -gt 0 ]; then mapfile -t v6 < <(printf '%s\n' "${v6[@]}" | sort -u); fi
say "${#project_hosts[@]} project-run hosts, ${#v4[@]} IPv4 and ${#v6[@]} IPv6 addresses to block"

join_set() {
  local IFS=,
  echo "$*"
}

sudo ip netns add "$ns"
ns_made=1
in_ns() { sudo ip netns exec "$ns" "$@"; }
# As the calling user, inside the namespace.
as_user() { sudo ip netns exec "$ns" setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"; }

sudo ip -n "$ns" link set lo up
# The only way out: a dummy interface that reaches nothing, with default
# routes through it, so that every attempt to leave meets the rule below
# instead of failing for want of a route.
sudo ip -n "$ns" link add gr0 type dummy
sudo ip -n "$ns" link set gr0 up
sudo ip -n "$ns" addr add 10.231.0.1/24 dev gr0
sudo ip -n "$ns" route add default dev gr0
sudo ip -n "$ns" -6 addr add fd67:686f:7374::1/64 dev gr0 nodad 2>/dev/null || true
sudo ip -n "$ns" -6 route add default dev gr0 2>/dev/null || true
# DNS inside the namespace goes to an address behind the rule.
[ -d /etc/netns ] || netns_dir_made=1
sudo mkdir -p "/etc/netns/$ns"
echo "nameserver 10.231.0.53" | sudo tee "/etc/netns/$ns/resolv.conf" >/dev/null

{
  echo "table inet ghost_recovery {"
  echo "  counter project_hits { }"
  echo "  counter egress { }"
  if [ "${#v4[@]}" -gt 0 ]; then
    echo "  set project4 { type ipv4_addr; elements = { $(join_set "${v4[@]}") } }"
  fi
  if [ "${#v6[@]}" -gt 0 ]; then
    echo "  set project6 { type ipv6_addr; elements = { $(join_set "${v6[@]}") } }"
  fi
  echo "  chain out {"
  echo "    type filter hook output priority 0; policy accept;"
  echo "    oifname \"lo\" accept"
  # The kernel's own IPv6 link control on the dummy interface (router
  # solicitations, multicast listener reports): ICMPv6 to link-local
  # multicast, which names no host and reaches none.
  echo "    ip6 daddr ff02::/16 meta l4proto ipv6-icmp accept"
  if [ "${#v4[@]}" -gt 0 ]; then echo "    ip daddr @project4 counter name \"project_hits\" reject"; fi
  if [ "${#v6[@]}" -gt 0 ]; then echo "    ip6 daddr @project6 counter name \"project_hits\" reject"; fi
  echo "    counter name \"egress\" reject"
  echo "  }"
  echo "}"
} | in_ns nft -f -

counter() {
  in_ns nft list counter inet ghost_recovery "$1" | awk '/packets/ {for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1)}'
}

# Self-check: a connection to a project-run address is refused and counted.
probe_addr="${v4[0]:-}"
if [ -n "$probe_addr" ]; then
  if as_user timeout 5 bash -c "exec 3<>/dev/tcp/$probe_addr/443" 2>/dev/null; then
    die "self-check: $probe_addr:443 answered from inside the namespace"
  fi
  [ "$(counter project_hits)" -gt 0 ] || die "self-check: the rule did not count a connection to $probe_addr"
else
  say "no project-run address resolved (offline?); the self-check uses the egress counter"
  if as_user timeout 5 bash -c "exec 3<>/dev/tcp/10.231.0.99/443" 2>/dev/null; then
    die "self-check: 10.231.0.99 answered"
  fi
  [ "$(counter egress)" -gt 0 ] || die "self-check: the rule did not count a connection out"
fi
say "self-check passed: the rule refuses and counts a connection out"

# Every project-run host, by name and by address, must be unreachable.
for h in "${project_hosts[@]}"; do
  if as_user timeout 5 getent hosts "$h" >/dev/null 2>&1; then
    die "the project-run host $h resolves from inside the namespace"
  fi
done
for addr in "${v4[@]}" "${v6[@]}"; do
  for port in 443 80; do
    if as_user timeout 5 bash -c "exec 3<>/dev/tcp/$addr/$port" 2>/dev/null; then
      die "the project-run address $addr port $port is reachable from inside the namespace"
    fi
  done
done
say "no project-run host is reachable from inside the namespace"
in_ns nft reset counters table inet ghost_recovery >/dev/null
if [ "$(counter project_hits)" != 0 ] || [ "$(counter egress)" != 0 ]; then
  die "the counters did not reset"
fi

# --- 3. The recovery, inside the namespace ---

results="$work/results.json"
log="$work/test.log"
say "running the recovery test in namespace $ns (this takes a while)"
set +e
as_user env -i \
  PATH="$PATH" HOME="$HOME" TMPDIR="$work" \
  GHOST_NODE_GETH="$geth_a" GHOST_WEBAPP_WASM="$wasm" \
  GHOST_RECOVERY_NETNS="$ns" GHOST_RECOVERY_RESULTS="$results" \
  node --test --test-reporter=spec --test-timeout=7200000 "$webapp/test/e2e/recovery.test.mjs" 2>&1 | tee "$log" >&2
test_status=${PIPESTATUS[0]}
set -e

# --- 4. Verdict ---

hits="$(counter project_hits)"
egress="$(counter egress)"
fail=0
if [ "$test_status" -ne 0 ]; then
  echo "recovery-blackout: FAIL: the recovery test failed (exit $test_status)" >&2
  fail=1
fi
if [ "$hits" != 0 ]; then
  echo "recovery-blackout: FAIL: $hits packets went to a project-run host during the run" >&2
  fail=1
fi
if [ "$egress" != 0 ]; then
  echo "recovery-blackout: FAIL: $egress packets tried to leave the internal network during the run" >&2
  fail=1
fi

expected=(partial-reveal-then-claim reorganisation-during-recovery older-tree-state rollover commitment-in-full-tree)
n_pass=0
if [ ! -s "$results" ]; then
  echo "recovery-blackout: FAIL: the test wrote no results" >&2
  fail=1
else
  # shellcheck disable=SC2016 # JavaScript, not shell
  summary="$(node -e '
    const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const want = process.argv.slice(2);
    let pass = 0, skip = 0, bad = 0;
    for (const name of want) {
      const c = r.find((x) => x.case === name);
      const result = c ? c.result : "missing";
      if (result === "pass") pass += 1; else if (result === "skip") skip += 1; else bad += 1;
      console.log(`  ${result.toUpperCase().padEnd(8)} ${name}${c && c.detail ? `: ${c.detail}` : ""}`);
    }
    console.log(`#counts ${pass} ${skip} ${bad}`);
  ' "$results" "${expected[@]}")"
  echo "recovery-blackout: cases:" >&2
  grep -v '^#counts' <<<"$summary" >&2
  read -r _ n_pass n_skip n_bad < <(grep '^#counts' <<<"$summary")
  if [ "$n_bad" -ne 0 ]; then fail=1; fi
  if [ "$n_skip" -gt 0 ]; then
    if [ "$require_all" = 1 ]; then
      echo "recovery-blackout: FAIL: $n_skip case(s) skipped, and --require-all allows none" >&2
      fail=1
    else
      say "$n_skip case(s) SKIPPED, not passed; see the reasons above"
    fi
  fi
fi

say "packets to project-run hosts: $hits; other packets out: $egress"
if [ "$fail" -ne 0 ]; then
  exit 1
fi
say "PASS: $n_pass case(s) passed with every project-run host blocked"
