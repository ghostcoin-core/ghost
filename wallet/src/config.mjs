// The wallet's two settings, kept in one place for a reviewer.

// The web app origins whose requests the wallet answers, and the only
// origins it posts to: where the web app is hosted.
export const WEBAPP_ORIGINS = Object.freeze(["https://ghost-webapp-alpha.vercel.app"]);

// The chain ids the wallet signs for: the test network. The launch id is
// added by the change that launches it.
export const CHAIN_IDS = Object.freeze([7777001n]);

// Ghost Guard, by chain id (as a decimal string). The wallet trusts these and
// nothing an app sends: a Guard commit goes only to the chain's coin commit
// entry, and the wallet makes, spends and names Guard coins only of the
// chain's Guard policy, its address and code hash. The coin commit entry is
// the native account "ghost" then 5 (ghost-node, params/ghost/privaccounts.go).
export const COMMIT_ENTRIES = Object.freeze({ 7777001: "0x67686f7374000000000000000000000000000005" });
// The Guard address and code hash are not final (spec 10, section 15, item
// 4), so no chain has one yet and every Guard request is refused until the
// change that deploys Guard adds it here, as
// { address: "0x...20 bytes", codehash: "0x...32 bytes" }.
export const GUARD_POLICIES = Object.freeze({});
