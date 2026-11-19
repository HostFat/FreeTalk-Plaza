# FreeTalk Plaza UI tests

Playwright end-to-end tests for the Dioxus UI. They run against the
`example-data` build, so they do not need a Freenet node, a delegate or a
contract.

## Run

From the repository root:

```powershell
pwsh ./test-e2e.ps1
```

Playwright runs `serve-example.mjs`: it builds `plaza-ui` with
`example-data,no-sync`, serves the static bundle on port 8082, runs the tests
and stops the server. Building before serving avoids running against a stale
wasm bundle. If a server is already listening on 8082, it is reused.

Manual alternative (with `dx` on `PATH`):

```powershell
cd ui/tests
npm install
npx playwright install chromium firefox webkit
npm test
```

Use `-Project chromium`, `-Project firefox` or `-Project webkit` for one
browser, or `-Headed` to watch the run. The projects are Chromium, Firefox,
WebKit and mobile Chrome. On CI the workflow installs the browsers with their
system dependencies and runs Playwright inside the Nix shell, which provides
`dx`.

## Fixtures

`example-data` seeds four boards:

| Board | Visible identity |
|---|---|
| `Public Discussion Board` | observer |
| `Team Chat Board` | member; contains `General` (inherits auto-moderation) and `NoAuto` (policy off) |
| `Your Private Board` | owner |
| `Owner Key, Member Profile` | member on a device that also holds the owner key; owner controls must stay hidden |

The test files:

- `identity-controls.spec.ts` — crown, Manage, groups and sections follow the visible profile.
- `section-policy.spec.ts` — the “Moderate replies” checkbox appears in `General` and is absent in `NoAuto`.
- `board-navigation.spec.ts` — every fixture board opens instead of staying on “Loading board…”.
- `invite-recovery.spec.ts` — a damaged invite link shows the recovery field.
- `mentions.spec.ts` — `@` autocomplete inserts a chip and clicking it opens the member info.
- `reactions.spec.ts` — hovering a reaction shows reactor names.

## CI

`.github/workflows/e2e.yml` runs the suite on every push and pull request to
`trunk`. It installs Chromium, Firefox and WebKit with `--with-deps`, runs
Playwright inside the Nix dev shell (for `dx`), and uploads `playwright-report`
and `test-results` when a test fails.

## Notes

- `serve-example.mjs` uses the static bundle, so the tests do not depend on
  the dev server or its websocket connection.
- The example data uses random keys and names each load. Do not hardcode board
  keys or member names in tests; select boards by their stable titles.
- `test-results/` and `playwright-report/` are generated and gitignored.
