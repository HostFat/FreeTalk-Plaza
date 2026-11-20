import { expect, test } from "@playwright/test";

// Local-only integration checks. Run with:
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts
const BASE = process.env.PLAZA_REAL_NODE_URL ?? "";
const BOARD_KEY = "294pw6U6MMPTiMCAWTgEbj4xv5ZQ7JgXLuhsWxoRk3wf";
async function createInviteLink(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  if (!(await app.getByRole("button", { name: /Manage/ }).count())) {
    await app.getByRole("button", { name: /FreeTalk Plaza/ }).click();
    const useOwner = app.getByRole("button", { name: "Use on this board" });
    if (await useOwner.count()) {
      await useOwner.last().click();
      await page.waitForTimeout(800);
    }
  }

  await page.goto(`${BASE}#/board/${BOARD_KEY}/admin/links`);
  // Only the hash changed: reload so the shell frame follows it.
  await page.reload();
  const role = app.getByRole("combobox").first();
  await expect(role).toBeVisible({ timeout: 30_000 });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible();
  return link.inputValue();
}

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

test("board archive survives a reload and can be restored", async ({ page }) => {
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });

  const openSwitcher = async () => {
    await app.getByRole("button", { name: /P480Private/ }).first().click();
  };
  const row = () =>
    app
      .locator("div.w-full.flex.items-center.gap-2")
      .filter({ hasText: "InviteTest" })
      .first();

  await openSwitcher();
  if (await row().getByTitle("Restore board").count()) {
    await row().getByTitle("Restore board").click();
  }
  await row().getByTitle("Archive board").click();
  await expect(app.getByText("Archived", { exact: true })).toBeVisible();
  await page.waitForTimeout(3_000);

  await page.reload();
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  await openSwitcher();
  await expect(
    app.getByRole("button", { name: /InviteTest/ }).first(),
  ).toBeVisible({ timeout: 30_000 });
  await expect(app.getByText("Archived", { exact: true })).toBeVisible();
  await expect(row().getByTitle("Restore board")).toBeVisible();
  await row().getByTitle("Restore board").click();
  await expect(row().getByTitle("Restore board")).toHaveCount(0);
});

test("a valid invite opens the join and a new identity joins", async ({
  page,
}) => {
  const invite = await createInviteLink(page);
  await page.goto(invite);
  await page.reload();
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

// The first post of an identity that joined through a reusable link is still
// lost after a reload: the local message is accepted optimistically but the
// membership + message delta does not survive. Keep the reproduction here.
test.fixme("an invited identity's first post survives a reload", async ({
  page,
}) => {
  const invite = await createInviteLink(page);
  await page.goto(invite);
  await page.reload();
  const app = page.frameLocator("iframe");
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill("RealNodeGuest");
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });

  await app.getByRole("heading", { name: "General" }).click();
  await app.getByRole("button", { name: /New Topic/ }).first().click();
  await app.getByPlaceholder("Add a title...").fill("Guest membership test");
  await app
    .locator("#message-input")
    .fill("Posted by the invited identity after joining.");
  await app.getByRole("button", { name: /Send Topic/ }).click();
  await expect(
    app.getByText("Guest membership test", { exact: true }).first(),
  ).toBeVisible({ timeout: 20_000 });

  await page.reload();
  await expect(
    app.getByText("Guest membership test", { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});
