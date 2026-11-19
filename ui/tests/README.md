# FreeTalk Plaza UI tests

Playwright end-to-end tests for the Dioxus UI. They run against the
`example-data` build, so they do not need a Freenet node, a delegate or a
contract.

## Run

From the repository root:

```powershell
pwsh ./test-e2e.ps1
```

The script starts `dx serve` on port 8082 with `example-data,no-sync`, waits
for the app, runs the tests and stops the server. If a server is already
listening on 8082, it is reused and left running.

Manual alternative:

```powershell
cd ui
dx serve --port 8082 --open false --hot-reload false --watch false `
  --features example-data,no-sync
```

Then, in another terminal:

```powershell
cd ui/tests
npm install
npx playwright install chromium
npm test
```

Use `-Project chromium` for one browser, or `-Headed` to watch the run.

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
- `reactions.spec.ts` — hovering a reaction shows reactor names.

## Notes

- The dev server's websocket warnings are expected: `no-sync` does not remove
  the node connection code, it only keeps the tests from depending on it.
- The example data uses random keys and names each load. Do not hardcode board
  keys or member names in tests; select boards by their stable titles.
- `test-results/` and `playwright-report/` are generated and gitignored.
