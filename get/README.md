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
carries a strict Content-Security-Policy and has no inline script.

## Test

```sh
node --test get/test/
```

The tests build from a temporary release folder of fixture scripts signed
with a key pair made in the test, and read `vercel/config.json` as text.
Nothing touches the network.
