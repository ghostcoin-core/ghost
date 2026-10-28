// `node --test webapp/test/` with Node 24 runs this folder as one module,
// which resolves to this file: it loads every test file of the web app.
// An ES module, as the web app's package.json sets.

import "./units.test.mjs";
import "./header-chain.test.mjs";
import "./header-store.test.mjs";
import "./early-reveal.test.mjs";
import "./reveal-moving-head.test.mjs";
import "./wasm.test.mjs";
import "./commit-layout.test.mjs";
import "./tree-shape.test.mjs";
import "./earlier-trees.test.mjs";
import "./note-buckets.test.mjs";
import "./spent-from-receipts.test.mjs";
import "./receipts-at.test.mjs";
import "./stand-in.test.mjs";
import "./flow.test.mjs";
import "./wallet-connect.test.mjs";
import "./vanish-approval.test.mjs";
import "./sent-and-done.test.mjs";
import "./block-pacer.test.mjs";
import "./page-layout.test.mjs";
import "./light-brand.test.mjs";
import "./vanish-screens.test.mjs";
import "./vanish-minimum.test.mjs";
import "./summon-screens.test.mjs";
import "./summon-confirm.test.mjs";
import "./summon-auto-wait.test.mjs";
import "./summon-payout.test.mjs";
import "./local-node-probe.test.mjs";
