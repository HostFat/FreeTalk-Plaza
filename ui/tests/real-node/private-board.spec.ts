import { expect, test } from "@playwright/test";

// Local-only integration checks. Run with:
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts
const BASE = process.env.PLAZA_REAL_NODE_URL ?? "";
async function gotoRoute(
  page: import("@playwright/test").Page,
  hash: string,
) {
  const url = new URL(BASE);
  url.searchParams.set("nav", Date.now().toString());
  url.hash = hash;
  await page.goto(url.toString());
}

const PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

async function ensureOwner(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  if (!(await app.getByRole("button", { name: /Manage/ }).count())) {
    await switchToProfile(page, "OwnerP");
  }
}
const BOARD_KEY = "294pw6U6MMPTiMCAWTgEbj4xv5ZQ7JgXLuhsWxoRk3wf";
async function switchToProfile(
  page: import("@playwright/test").Page,
  name: string,
) {
  const app = page.frameLocator("iframe");
  await app.getByRole("button", { name: /FreeTalk Plaza/ }).click();
  const row = app
    .locator(".about-modal .profile-row")
    .filter({ hasText: name })
    .first();
  await row.getByRole("button", { name: "Use on this board" }).click();
  await page.waitForTimeout(2_000);
  if (name === "OwnerP") {
    await expect(
      app.getByRole("button", { name: /Manage/ }),
    ).toBeVisible({ timeout: 10_000 });
  }
}

async function createInviteLink(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  if (!(await app.getByRole("button", { name: /Manage/ }).count())) {
    await switchToProfile(page, "OwnerP");
  }

  const linksUrl = new URL(BASE);
  linksUrl.searchParams.set("links", Date.now().toString());
  linksUrl.hash = `/board/${BOARD_KEY}/admin/links`;
  await page.goto(linksUrl.toString());
  const role = app.getByRole("combobox").first();
  await expect(role).toBeVisible({ timeout: 30_000 });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible();
  const value = await link.inputValue();
  // The token has to reach the board contract before the invited client
  // fetches the state; otherwise the join proof references an inactive token.
  await page.waitForTimeout(3_000);
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 30_000,
  });
  return value;
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

test("board order survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  const rows = () => app.locator("div.w-full.flex.items-center.gap-2");
  const names = () =>
    rows().evaluateAll((elements) =>
      elements.map((element) => element.innerText.split("\n")[0]),
    );
  const rowFor = (name: string) =>
    rows().filter({ hasText: name }).first();

  await app.getByRole("button", { name: /P480Private/ }).first().click();
  const before = await names();
  const moved = before[1];
  await rowFor(moved).getByTitle("Move board up").click();
  expect((await names())[0]).toBe(moved);
  await page.waitForTimeout(1_500);

  await page.reload();
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });
  await app.getByRole("button", { name: /P480Private/ }).first().click();
  expect((await names())[0]).toBe(moved);

  // The board order assertion above is the subject of this test; leaving the
  // local order changed is harmless.
});

test("a valid invite opens the join and a new identity joins", async ({
  page,
}) => {
  const invite = await createInviteLink(page);
  const joinUrl = new URL(invite);
  joinUrl.searchParams.set("guest", Date.now().toString());
  await page.goto(joinUrl.toString());
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
test("an image uploads and survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  const app = page.frameLocator("iframe");
  await app.getByText("P480Private").first().waitFor({ timeout: 30_000 });
  await ensureOwner(page);

  await app.getByRole("heading", { name: "General" }).click();
  await app.getByRole("button", { name: /New Topic/ }).first().click();
  const title = `Image test ${Date.now()}`;
  await app.getByPlaceholder("Add a title...").fill(title);
  await app.locator("#message-input").fill("A pixel image.");
  await app.locator("#image-file-input-test").setInputFiles({
    name: "pixel.png",
    mimeType: "image/png",
    buffer: PIXEL_PNG,
  });

  await expect(
    app.getByText("pixel.png", { exact: false }).first(),
  ).toBeVisible({ timeout: 30_000 });
  const send = app.getByRole("button", { name: /Send Topic/ });
  await expect(send).toBeEnabled({ timeout: 60_000 });
  await send.click();
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });

  await page.reload();
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});

test.fixme("a hidden topic is restored from the trash", async ({ page }) => {
  // A fresh board makes the current profile the owner, so the trash flow does
  // not depend on which profile was active in an earlier test.
  const boardName = `Trash board ${Date.now()}`;
  await page.goto(`${BASE}#/`);
  const app = page.frameLocator("iframe");
  await app.getByText("Select or Create Board", { exact: true }).click();
  await app.getByRole("button", { name: "Create Board", exact: true }).click();
  await app.getByPlaceholder("Enter board name").fill(boardName);
  await app.getByPlaceholder("Enter your nickname").fill("TrashOwner");
  await app.getByRole("checkbox", { name: "Private board" }).check();
  await app.getByRole("button", { name: "Create Board" }).last().click();
  await app.getByText(boardName, { exact: true }).first().waitFor({
    timeout: 30_000,
  });
  const boardKey = new URL(page.url()).hash.match(/\/board\/([^/]+)/)?.[1];
  expect(boardKey).toBeTruthy();

  await app.getByRole("button", { name: /\+ Section/ }).first().click();
  await app.locator("input").first().fill("General");
  await app.getByRole("button", { name: "Create Section" }).click();
  await app.getByRole("heading", { name: "General" }).click();

  await app.getByRole("button", { name: /New Topic/ }).first().click();
  const title = `Trash test ${Date.now()}`;
  await app.getByPlaceholder("Add a title...").fill(title);
  await app.locator("#message-input").fill("This topic is hidden and restored.");
  await app.getByRole("button", { name: /Send Topic/ }).click();
  await app.getByText(title, { exact: true }).first().click();

  page.once("dialog", (dialog) => dialog.accept("severe test hide"));
  await app.getByRole("button", { name: "Hide" }).click();
  await page.waitForTimeout(1_000);

  await gotoRoute(page, `/board/${boardKey}/admin/trash`);
  await app.getByText("Trash", { exact: true }).first().waitFor({
    timeout: 30_000,
  });
  await app.getByRole("button", { name: "Restore" }).first().click();
  await page.waitForTimeout(1_000);

  await gotoRoute(page, `/board/${boardKey}`);
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});

test("an invited identity's first post survives a reload", async ({ page }) => {
  const invite = await createInviteLink(page);
  const joinUrl = new URL(invite);
  joinUrl.searchParams.set("guest", Date.now().toString());
  await page.goto(joinUrl.toString());
  const app = page.frameLocator("iframe");
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill("RealNodeGuest");
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText("P480Private").first()).toBeVisible({
    timeout: 30_000,
  });

  const title = `Guest membership test ${Date.now()}`;
  await app.getByRole("heading", { name: "General" }).click();
  await app.getByRole("button", { name: /New Topic/ }).first().click();
  await app.getByPlaceholder("Add a title...").fill(title);
  await app
    .locator("#message-input")
    .fill("Posted by the invited identity after joining.");
  await app.getByRole("button", { name: /Send Topic/ }).click();
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 20_000 });

  // Capture the exact guest profile row (nickname plus short id); many test
  // runs leave profiles with the same nickname.
  await app.getByRole("button", { name: /FreeTalk Plaza/ }).click();
  const guestLabel = (
    await app
      .locator(".about-modal .profile-row")
      .filter({ hasText: "RealNodeGuest" })
      .filter({ hasText: "current here" })
      .first()
      .innerText()
  ).trim();
  const guestId = guestLabel
    .split("\n")
    .map((line) => line.trim())
    .find((line) => /^[1-9A-HJ-NP-Za-km-z]{8}$/.test(line)) ?? guestLabel;
  await app.getByRole("button", { name: "Close" }).click();

  // The owner reload seals the board secret to the new member.
  await switchToProfile(page, "OwnerP");
  await page.reload();
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  await app.getByText("P480Private").first().waitFor({ timeout: 30_000 });
  await page.waitForTimeout(5_000);

  // Return to the invited identity and reload.
  await switchToProfile(page, guestId);
  await page.reload();
  await page.goto(`${BASE}#/board/${BOARD_KEY}`);
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});
