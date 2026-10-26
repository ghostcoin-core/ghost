// The headers the page checked, kept in the page's own IndexedDB between
// sessions (public header fields only): createHeaderStore(indexedDB), the
// flow's `headerStore`. The code is in header.mjs, whose part "The headers
// the page checked, kept between sessions" describes the store; it lives
// there because the build (build.sh) ships a fixed list of modules that
// header.mjs is on.

export { HEADER_DATABASE, createHeaderStore } from "./header.mjs";
