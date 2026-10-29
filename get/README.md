# get.ghostcoin.com

The one-line Ghost node install and its Run a node page. A static site in
the Vercel Build Output layout, like `webapp/`: plain ES modules, no
framework and no dependencies.

| URL | Serves |
| --- | --- |
| `/` from curl, Wget or PowerShell | `install.sh`, the Mac and Linux script |
| `/` from anything else | the Run a node page |
| `/win` | the PowerShell script, `install.ps1` |
| `/cmd` | the CMD script, `install.cmd` |

The lines the page shows:

```text
curl -fsSL https://get.ghostcoin.com | sh
irm https://get.ghostcoin.com/win | iex
curl -fsSL https://get.ghostcoin.com/cmd -o ghost-install.cmd && ghost-install.cmd && del ghost-install.cmd
```

The page finds the visitor's system from the user agent (Windows, macOS,
otherwise Linux), shows that system's line with one copy button, and lists
the other systems below it.

A notice near the top says this is the Ghost public test network: its coins
are test coins with no value, and the network may be reset, in which case
nodes move to the new chain on their own. Under the install line, for people
who use the Ghost web app, the same install mines straight to their Ghost
wallet with `GHOST_MINE_TO` set to the wallet's address:

```text
curl -fsSL https://get.ghostcoin.com | GHOST_MINE_TO=0xYOUR_WALLET_ADDRESS sh
$env:GHOST_MINE_TO='0xYOUR_WALLET_ADDRESS'; irm https://get.ghostcoin.com/win | iex
```

## Look

One light theme, matching the web app and brand: the palette is the set of
tokens in `style.css`'s `:root` (white page, `#6B4CFF` violet accent, the
install line in a dark `#0E0D1A` box), and every text color meets WCAG AA
on its background. The logo is the pixel ghost: inline in `index.html` the
full logo (outlined cells on a lavender body, the eyes left empty), and as
`favicon.svg` its small cut for 16 to 32 px (the body alone in violet).

The fonts are self-hosted from `fonts/`: the latin-subset woff2 files of
the `@fontsource/instrument-sans` (400, 600) and `@fontsource/ibm-plex-mono`
(400) packages, unmodified, under the SIL Open Font License
(`fonts/LICENSE.txt`). `test/brand.test.mjs` checks the palette, the
contrast, the logo's geometry and the fonts.

## Build

```sh
node get/build.mjs
```

`build.mjs` takes the scripts from the latest release of
`ghostcoin-core/ghost-node` (its `releases/latest/download` URLs), or from
the folder `GET_RELEASE_DIR` names, and never from a branch. Each script
comes with a `.sig` file, the raw 64-byte ed25519 signature of its bytes,
checked against `release-key.pub`, a copy of ghost-node's
`install/release-key.pub`.

It fails closed:

- `install.sh` missing, unsigned or failing its check: the build exits
  non-zero and leaves no `get/dist`.
- `install.ps1` or `install.cmd` missing, or without a signature: the build
  succeeds, `/win` or `/cmd` serves a stub that only says the Windows
  installer is not published yet and fails, and the page shows that system
  as coming soon with no copy button.
- A bad signature on any script: the build fails.

## Deploy

`get/dist` is the site's static folder and `get/vercel/config.json` its
routes and headers:

```sh
cp -R get/dist/. .vercel/output/static/
cp get/vercel/config.json .vercel/output/config.json
vercel deploy --prebuilt --prod
```

Scripts are served as `text/plain; charset=utf-8` with
`X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. The page
carries a strict Content-Security-Policy and has no inline script; it loads
only its own script, stylesheet, favicon and fonts.

## Test

```sh
node --test get/test/
```

The tests build from a temporary release folder of fixture scripts signed
with a key pair made in the test, and read `vercel/config.json` as text.
Nothing touches the network.
