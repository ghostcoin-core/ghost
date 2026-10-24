// The wallet's two settings, kept in one place for a reviewer.

// The web app origins whose requests the wallet answers, and the only
// origins it posts to. The host step sets the real ones.
export const WEBAPP_ORIGINS = Object.freeze(["https://app.ghostcoin.com"]);

// The chain ids the wallet signs for: the test network. The launch id is
// added by the change that launches it.
export const CHAIN_IDS = Object.freeze([7777001n]);
