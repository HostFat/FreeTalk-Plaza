import { expect, test } from "@playwright/test";

// Local-only integration checks. Run with:
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts
const BASE = process.env.PLAZA_REAL_NODE_URL ?? "";
const BOARD_KEY = "294pw6U6MMPTiMCAWTgEbj4xv5ZQ7JgXLuhsWxoRk3wf";
const INVITE_TOKEN =
  "294xhCnQ5DnBUv7TSDGA3cANNnx4N4st5KKneoJdTucwMx22aLsDHGKc1eS7GqCPZSDGSBmmyGE5y9mMCP8VfT17mhqeEGpJLSs8c8QT2KSkPxAhS149so5aqNjPQuQMNTx2qsS8FHnRs8tLq6i45FxLAAxaxxgSqZk9QmWrxoWKAfzcm9WBrrhatFDZeGJhzEUf3h9qJwPW4Jw5xgsq2pCKqH";

test("a private board recovers its key after a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  const app = page.frameLocator("iframe");

  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText("AutoModP480").first()).toBeVisible({
    timeout: 20_000,
  });

  await page.reload();
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(
    app.getByText("Loading board…", { exact: true }),
  ).toHaveCount(0);
  await expect(app.getByText("AutoModP480").first()).toBeVisible({
    timeout: 20_000,
  });
});

test("the notification mode survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${BOARD_KEY}/notifications`);
  const app = page.frameLocator("iframe");
  const mode = app.locator("#notification-mode");
  await expect(mode).toBeVisible({ timeout: 30_000 });

  await mode.selectOption("muted");
  await page.waitForTimeout(1_000);
  await page.reload();
  await expect(mode).toHaveValue("muted", { timeout: 30_000 });

  await mode.selectOption("all");
});

test("a valid invite opens the join and a new identity joins", async ({
  page,
}) => {
  await page.goto(`${BASE}#/join/${INVITE_TOKEN}`);
  const app = page.frameLocator("iframe");

  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill("RealNodeGuest");
  await app.getByRole("button", { name: "Join" }).click();

  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
});
