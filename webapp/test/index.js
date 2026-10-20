// `node --test webapp/test/` with Node 24 runs this folder as one module,
// which resolves to this file: it loads every test file of the web app.
// An ES module, as the web app's package.json sets.

import "./units.test.mjs";
import "./early-reveal.test.mjs";
import "./wasm.test.mjs";
import "./commit-layout.test.mjs";
import "./tree-shape.test.mjs";
import "./stand-in.test.mjs";
import "./flow.test.mjs";
