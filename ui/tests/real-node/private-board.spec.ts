import { expect, test } from "@playwright/test";

// Local-only integration checks. Run with:
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts
//
// The suite provisions its own boards: it clears the local delegate store and
// creates a private board plus a second board for archive/order checks. This
// keeps every run independent of the data left by earlier runs.
const BASE = process.env.PLAZA_REAL_NODE_URL ?? "";
const MAIN_BOARD = "P480Private";
const SECOND_BOARD = "InviteTest";
const OWNER = "OwnerP";
// A valid key that is never stored on the node; the board gate offers "Reset
// local data" for it.
const RESET_KEY = "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB";
let boardKey = "";

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

async function appFrame(page: import("@playwright/test").Page) {
  const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
  if (!frame) throw new Error("The app iframe is not available");
  return frame;
}

async function waitForBoardRoute(page: import("@playwright/test").Page) {
  let key = "";
  await expect
    .poll(
      async () => {
        const hash = await (await appFrame(page)).evaluate(() => location.hash);
        const match = hash.match(/#\/board\/([1-9A-HJ-NP-Za-km-z]+)/);
        if (match) key = match[1];
        return Boolean(match);
      },
      { timeout: 30_000 },
    )
    .toBe(true);
  return key;
}

async function createBoard(
  page: import("@playwright/test").Page,
  name: string,
  nickname: string,
  privateBoard: boolean,
  useExistingProfile = false,
) {
  const app = page.frameLocator("iframe");
  const trigger = app
    .locator('div[role="button"]')
    .filter({
      has: app.getByText(/Select or Create Board|P480Private|InviteTest/, {
        exact: true,
      }),
    })
    .first();
  await trigger.click();
  await app
    .getByRole("button", { name: "Create Board", exact: true })
    .click();
  await app.getByPlaceholder("Enter board name").fill(name);
  if (useExistingProfile) {
    await app.locator("select").first().selectOption({ label: nickname });
    // The select fills this from the profile, but writing it keeps the test
    // independent of the event timing.
    await app.getByPlaceholder("Enter your nickname").fill(nickname);
  } else {
    await app.getByPlaceholder("Enter your nickname").fill(nickname);
  }
  if (privateBoard) {
    await app.getByRole("checkbox").check();
  }
  await app
    .getByRole("button", { name: "Create Board", exact: true })
    .click();
  const key = await waitForBoardRoute(page);
  try {
    await expect(app.getByText(name).first()).toBeVisible({ timeout: 30_000 });
  } catch (error) {
    console.log(
      `board ${name} did not open; body:\n` +
        (await app.locator("body").innerText()).slice(-1200),
    );
    throw error;
  }
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 60_000,
  });
  // The board PUT and the delegate save run in the background.
  await page.waitForTimeout(6_000);
  return key;
}

async function ensureOwner(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  if (!(await app.locator('span[title="Board Owner"]').count())) {
    await switchToProfile(page, OWNER);
  }
}

async function waitForSync(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 30_000,
  });
}

async function switchToProfile(
  page: import("@playwright/test").Page,
  name: string,
) {
  const app = page.frameLocator("iframe");
  const rows = () =>
    app
      .locator(".device-drawer .profile-row")
      .filter({ has: app.getByText(name, { exact: true }) });

  const openDrawer = async () => {
    if (await app.locator(".device-drawer").count()) return;
    await waitForSync(page);
    const profileButton = app.getByRole("button", { name: "Open identities" });
    if (await profileButton.count()) {
      await profileButton.click();
    } else {
      await app
        .getByRole("button", { name: "About, build and backup" })
        .click();
      await app
        .getByRole("button", { name: /Identities and backup/ })
        .click();
    }
    await app.locator(".device-drawer").waitFor({ timeout: 10_000 });
  };

  // Several test runs can create profiles with the same nickname. Try each
  // row until the owner profile (crown title "Board Owner") is active.
  for (let attempt = 0; attempt < 8; attempt++) {
    await openDrawer();
    const count = await rows().count();
    let tried = false;
    for (let index = 0; index < count; index++) {
      const row = rows().nth(index);
      const button = row.getByRole("button", { name: "Use on this board" });
      if ((await button.count()) === 0) continue;
      tried = true;
      await button.click();
      try {
        await expect(
          app.getByText(/Identity switched|Could not (save|switch)/),
        ).toBeVisible({ timeout: 60_000 });
      } catch (error) {
        const body = await app.locator("body").innerText();
        console.log("no switch toast; body tail:\n" + body.slice(-1200));
        throw error;
      }
      try {
        await expect(app.getByText("Identity switched.")).toBeVisible({
          timeout: 10_000,
        });
      } catch {
        const body = await app.locator("body").innerText();
        const line =
          body
            .split("\n")
            .find((text) => /Could not (save|switch)/.test(text)) ??
          body.slice(0, 600);
        throw new Error(`Profile switch failed: ${line}`);
      }
      if (name !== OWNER) return;
      if (await app.locator('span[title="Board Owner"]').count()) return;
      // A duplicate nickname that is not the board owner. Let the toast clear
      // and try the next row.
      await app
        .getByText("Identity switched.")
        .waitFor({ state: "detached", timeout: 15_000 })
        .catch(() => {});
      break;
    }
    if (!tried) break;
  }
  throw new Error(`Could not switch to the owner profile ${name}`);
}

async function createInviteLink(page: import("@playwright/test").Page) {
  const app = page.frameLocator("iframe");
  await page.goto(`${BASE}#/board/${boardKey}`);
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  if (!(await app.locator('span[title="Board Owner"]').count())) {
    await switchToProfile(page, OWNER);
  }

  const linksUrl = new URL(BASE);
  linksUrl.searchParams.set("links", Date.now().toString());
  linksUrl.hash = `/board/${boardKey}/admin/links`;
  await page.goto(linksUrl.toString());
  // The route selects the tab, but a reload can land on the default tab while
  // the board state loads. Clicking it explicitly makes the test independent.
  await app.getByRole("button", { name: "Invite links" }).click();
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

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  page.on("dialog", (dialog) => dialog.accept());
  const app = page.frameLocator("iframe");

  // Clear the delegate store so the run starts from a known state.
  await gotoRoute(page, `/board/${RESET_KEY}`);
  const reset = app.getByRole("button", { name: "Reset local data" });
  await expect(reset).toBeVisible({ timeout: 30_000 });
  await reset.click();
  await page.waitForTimeout(2_000);
  await page.goto(BASE);
  await expect(app.getByText(/Select or Create Board/).first()).toBeVisible({
    timeout: 30_000,
  });

  boardKey = await createBoard(page, MAIN_BOARD, OWNER, true);
  await expect(app.getByRole("button", { name: "+ Section" })).toBeVisible({
    timeout: 30_000,
  });
  await app.getByRole("button", { name: "+ Section" }).click();
  await app.getByPlaceholder("Category name").fill("General");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByRole("heading", { name: "General" })).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 60_000,
  });
  await page.waitForTimeout(6_000);

  // Invite links target a role. Create the "Members" role that the join
  // tests select on the links page.
  const rolesUrl = new URL(BASE);
  rolesUrl.searchParams.set("roles", Date.now().toString());
  rolesUrl.hash = `/board/${boardKey}/admin/roles`;
  await page.goto(rolesUrl.toString());
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByText("No roles yet.")).toHaveCount(0, {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 60_000,
  });
  await page.waitForTimeout(6_000);

  await createBoard(page, SECOND_BOARD, OWNER, false, true);
  await gotoRoute(page, `/board/${boardKey}`);
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  await page.close();
});

test("a private board recovers its key after a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${boardKey}`);
  const app = page.frameLocator("iframe");

  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  const general = app.getByRole("heading", { name: "General" });
  await expect(general).toBeVisible({ timeout: 20_000 });

  await page.reload();
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(
    app.getByText("Loading board…", { exact: true }),
  ).toHaveCount(0);
  await expect(app.getByText("Board key missing", { exact: true })).toHaveCount(
    0,
  );
  await expect(general).toBeVisible({ timeout: 20_000 });
});

test("the notification mode survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${boardKey}/notifications`);
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
  await page.goto(`${BASE}#/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });

  const openSwitcher = async () => {
    await app.getByRole("button", { name: /P480Private/ }).first().click();
  };
  const row = () =>
    app
      .locator("div.w-full.flex.items-center.gap-2")
      .filter({ hasText: SECOND_BOARD })
      .first();

  await openSwitcher();
  if (await row().getByTitle("Restore board").count()) {
    await row().getByTitle("Restore board").click();
  }
  await row().getByTitle("Archive board").click();
  await expect(app.getByText("Archived", { exact: true })).toBeVisible();
  // The archive flag is saved asynchronously; wait for the delegate write.
  await page.waitForTimeout(5_000);

  await page.reload();
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
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
  await expect(app.getByText("Archived", { exact: true })).toHaveCount(0);
  // Let the restore reach the delegate before the next test reloads.
  await page.waitForTimeout(5_000);
});

test("board order survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  const rows = () => app.locator("div.w-full.flex.items-center.gap-2");
  const names = () =>
    rows().evaluateAll((elements) =>
      elements.map((element) => element.innerText.split("\n")[0]),
    );
  const rowFor = (name: string) => rows().filter({ hasText: name }).first();

  await app.getByRole("button", { name: /P480Private/ }).first().click();
  // A previous archive test can leave the second board archived; restore it
  // before looking for the move controls.
  const secondRow = rowFor(SECOND_BOARD);
  if (await secondRow.getByTitle("Restore board").count()) {
    await secondRow.getByTitle("Restore board").click();
    await expect(secondRow.getByTitle("Restore board")).toHaveCount(0);
    await page.waitForTimeout(5_000);
  }
  const before = await names();
  const moved = before[1];
  await rowFor(moved).getByTitle("Move board up").click();
  expect((await names())[0]).toBe(moved);
  // The order is saved asynchronously; with many boards the delegate write
  // can take a few seconds.
  await page.waitForTimeout(5_000);

  await page.reload();
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
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

  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
});

test("an image uploads and survives a reload", async ({ page }) => {
  await page.goto(`${BASE}#/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
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
  await expect(app.getByText(/Uploading/)).toHaveCount(0, {
    timeout: 120_000,
  });
  const send = app.getByRole("button", { name: /Send Topic/ });
  await expect(send).toBeEnabled({ timeout: 60_000 });
  await send.click();
  await waitForSync(page);
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 60_000 });

  await page.reload();
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});

test("the DM delegate registers and keeps a device", async ({ page }) => {
  const logs: string[] = [];
  page.on("console", (message) => logs.push(message.text()));
  await gotoRoute(page, `/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });

  await expect
    .poll(() => logs.join("\n").includes("DM delegate registered"), {
      timeout: 30_000,
    })
    .toBe(true);

  // Selecting the board through the UI triggers the profile-bound identity
  // setup. Reset the DM delegate first so the new run's profile can initialize
  // even when a previous run left a different identity on this node.
  await gotoRoute(page, "/");
  await app
    .getByRole("button", { name: "About, build and backup" })
    .click();
  await app
    .getByRole("button", { name: /Identities and backup/ })
    .click();
  const drawer = app.locator(".device-drawer");
  await drawer.getByText("Developer", { exact: true }).click();
  page.once("dialog", (dialog) => dialog.accept());
  await drawer
    .getByRole("button", { name: "Reset DM delegate" })
    .click();
  await expect(app.getByText(/DM delegate reset/)).toBeVisible({
    timeout: 30_000,
  });
  await app.getByRole("button", { name: "Close" }).first().click();

  await app
    .getByRole("button", { name: /Select or Create Board/ })
    .first()
    .click();
  await app.getByRole("button", { name: MAIN_BOARD }).last().click();
  try {
    await expect
      .poll(
        () => /DM identity: \d+ device\(s\) registered/.test(logs.join("\n")),
        {
          timeout: 30_000,
        },
      )
      .toBe(true);
  } catch (error) {
    console.log("DM LOGS:\n" + logs.join("\n"));
    throw error;
  }
  expect(logs.join("\n")).not.toContain("DM delegate did not become ready");
});

test("a DM conversation contract is created and a message round-trips", async ({
  page,
}) => {
  await gotoRoute(page, `/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });

  await app.getByRole("button", { name: "Messages" }).first().click();
  await app.getByRole("button", { name: "New conversation" }).click();
  // A new conversation opens its chat view directly.
  await expect(app.getByRole("button", { name: "Invite" })).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText(/1 member\(s\)/)).toBeVisible({
    timeout: 30_000,
  });

  await app.getByPlaceholder("Write a message…").fill("hello from the DM test");
  await app.getByRole("button", { name: "Send", exact: true }).click();
  await expect(app.getByText("hello from the DM test")).toBeVisible({
    timeout: 60_000,
  });

  await app.getByRole("button", { name: "Invite" }).click();
  await expect(app.locator("#dm-invite-link")).toBeVisible({
    timeout: 30_000,
  });

  // The conversation index and the conversation key live in the delegate, so
  // the conversation and its plaintext come back after a reload.
  await page.reload();
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: "Messages" }).first().click();
  const restored = app.locator(".dm-conversation-row").first();
  await expect(restored).toBeVisible({ timeout: 30_000 });
  await restored.click();
  await expect(app.getByText("hello from the DM test")).toBeVisible({
    timeout: 30_000,
  });
});

// Delegate/core two-identity tests cover sealing, member addition and
// message encryption. The browser join test still sees a stale app bundle on
// the join route in the harness, so it stays fixme until the shell serves a
// deterministic bundle for in-app route changes.
test.fixme("an invited DM identity joins and sends a message", async ({ page }) => {
  const joinLogs: string[] = [];
  page.on("console", (message) => joinLogs.push(message.text()));
  await gotoRoute(page, `/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });

  // Create a second profile deterministically instead of depending on a
  // profile left by another test.
  const boardInvite = await createInviteLink(page);
  await page.goto(boardInvite);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill("DMGuest");
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });
  await switchToProfile(page, "OwnerP");

  await app.getByRole("button", { name: "Messages" }).first().click();
  await app.getByRole("button", { name: "New conversation" }).click();
  await expect(app.getByRole("button", { name: "Invite" })).toBeVisible({
    timeout: 60_000,
  });
  await app.getByRole("button", { name: "Invite" }).click();
  const inviteInput = app.locator("#dm-invite-link");
  await expect(inviteInput).toBeVisible({ timeout: 30_000 });
  const inviteLink = await inviteInput.inputValue();
  await page.waitForTimeout(3_000);
  await app.getByRole("button", { name: "Close" }).first().click();

  await page.goto(`${BASE}#/board/${boardKey}`);
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await switchToProfile(page, "DMGuest");

  // Navigate inside the running app: a full page load of the join URL can
  // serve a previously cached app bundle, while the in-app route always uses
  // the current build and the profile just selected.
  const joinHash = new URL(inviteLink).hash;
  const frame = await appFrame(page);
  await frame.evaluate((hash) => {
    window.location.hash = hash;
  }, joinHash);
  try {
    await expect(
      app.getByRole("button", { name: "Open conversation" }),
    ).toBeVisible({ timeout: 90_000 });
  } catch (error) {
    console.log(
      "JOIN PAGE BODY:\n" + (await app.locator("body").innerText()).slice(-1500),
    );
    console.log(
      "JOIN PAGE LOGS:\n" +
        joinLogs
          .filter((line) => /DM join|DM identity|invite|profile/i.test(line))
          .slice(-40)
          .join("\n"),
    );
    throw error;
  }
  await app.getByRole("button", { name: "Open conversation" }).click();
  await gotoRoute(page, `/board/${boardKey}`);
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: "Messages" }).first().click();
  try {
    await expect(app.getByText(/2 member\(s\)/)).toBeVisible({
      timeout: 60_000,
    });
  } catch (error) {
    console.log(
      "JOIN BODY:\n" + (await app.locator("body").innerText()).slice(-1800),
    );
    console.log(
      "JOIN LOGS:\n" +
        joinLogs
          .filter((line) => /DM join|DM identity|profile/i.test(line))
          .slice(-30)
          .join("\n"),
    );
    throw error;
  }
  await app.getByPlaceholder("Write a message…").fill("hello from the invited DM");
  await app.getByRole("button", { name: "Send", exact: true }).click();
  await expect(app.getByText("hello from the invited DM")).toBeVisible({
    timeout: 60_000,
  });

  await app.getByRole("button", { name: "Close" }).first().click();
  await gotoRoute(page, `/board/${boardKey}`);
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await switchToProfile(page, "OwnerP");
  await page.reload();
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: "Messages" }).first().click();
  const restored = app.locator(".dm-conversation-row").first();
  await expect(restored).toBeVisible({ timeout: 30_000 });
  await restored.click();
  await expect(app.getByText("hello from the invited DM")).toBeVisible({
    timeout: 30_000,
  });
});

test("a hidden topic is restored from the trash", async ({ page }) => {
  await page.goto(`${BASE}#/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await ensureOwner(page);

  await app.getByRole("heading", { name: "General" }).click();
  await app.getByRole("button", { name: /New Topic/ }).first().click();
  const title = `Trash test ${Date.now()}`;
  await app.getByPlaceholder("Add a title...").fill(title);
  await app.locator("#message-input").fill("This topic is hidden and restored.");
  await app.getByRole("button", { name: /Send Topic/ }).click();
  await app.getByText(title, { exact: true }).first().click();
  await waitForSync(page);
  await page.waitForTimeout(2_000);

  page.once("dialog", (dialog) => dialog.accept("severe test hide"));
  await app.getByRole("button", { name: "Hide" }).click();
  await expect(app.getByText(title, { exact: true })).toHaveCount(0, {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 30_000,
  });

  // Stay in the same page: Manage is the owner UI and preserves the profile.
  await app.getByRole("button", { name: /Manage/ }).click();
  await app.getByRole("button", { name: "Trash", exact: true }).click();
  await app.getByText("Trash", { exact: true }).first().waitFor({
    timeout: 30_000,
  });

  // The trash shows message ids, not titles. The hidden topic is the newest
  // entry, so its preview must contain the body before we restore it.
  const newest = app
    .locator("div.border.border-border.rounded-lg")
    .filter({ has: app.getByRole("button", { name: "Restore" }) })
    .first();
  await newest.getByRole("button", { name: "Preview" }).click();
  await expect(
    app.getByText("This topic is hidden and restored.").first(),
  ).toBeVisible({ timeout: 20_000 });
  await app.getByRole("button", { name: "Close" }).click();
  await newest.getByRole("button", { name: "Restore" }).click();
  await expect(app.getByText(/Topic restored/)).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, {
    timeout: 30_000,
  });

  await gotoRoute(page, `/board/${boardKey}`);
  await page.reload();
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("heading", { name: "General" }).click();
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});

test("a Mail address publishes on the board and survives a reload", async ({
  page,
}) => {
  await gotoRoute(page, `/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await ensureOwner(page);

  await app.getByRole("button", { name: "Open identities" }).click();
  const drawer = app.locator(".device-drawer");
  await drawer.getByRole("tab", { name: "Mail" }).click();
  const address = "3x4g3um9JYXLchv5VE3SD8wW9TnR8oSMLAA7AYfodBFc";
  await drawer.locator("#mail-address").fill(address);
  await drawer.getByRole("button", { name: "Save address" }).click();
  await drawer.getByRole("button", { name: "Board members" }).click();
  await expect(
    drawer.getByText(`Published on this board: ${address}`),
  ).toBeVisible({ timeout: 30_000 });
  await waitForSync(page);
  await page.waitForTimeout(5_000);
  await drawer.getByRole("button", { name: "Close" }).click();

  await page.reload();
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: "Open identities" }).click();
  await drawer.getByRole("tab", { name: "Mail" }).click();
  await expect(drawer.locator("#mail-address")).toHaveValue(address);
  await expect(
    drawer.getByText(`Published on this board: ${address}`),
  ).toBeVisible({ timeout: 30_000 });

  // The member profile or member info shows the published address.
  await drawer.getByRole("button", { name: "Close" }).click();
  await app.getByRole("button", { name: /Members/ }).click();
  await app.getByRole("button", { name: /OwnerP/ }).first().click();
  await expect(app.getByText("Freenet Mail").first()).toBeVisible({
    timeout: 30_000,
  });
  const frame = await appFrame(page);
  await expect
    .poll(
      async () => {
        if (await frame.getByText(address, { exact: false }).count()) {
          return true;
        }
        return frame
          .locator("input")
          .evaluateAll(
            (elements, value) =>
              elements.some(
                (element) => (element as HTMLInputElement).value === value,
              ),
            address,
          );
      },
      { timeout: 30_000 },
    )
    .toBe(true);

  // The member list exposes a quick Mail link.
  await gotoRoute(page, `/board/${boardKey}/members`);
  await expect(
    app.locator('a[title*="Open Freenet Mail"]').first(),
  ).toBeVisible({ timeout: 30_000 });

  await gotoRoute(page, `/board/${boardKey}`);
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: "Open identities" }).click();
  await drawer.getByRole("tab", { name: "Mail" }).click();
  await drawer.getByRole("button", { name: "Hidden" }).click();
  await expect(
    drawer.getByText(`Published on this board: ${address}`),
  ).toHaveCount(0, { timeout: 30_000 });
});

test("the board Mail contact survives a reload", async ({ page }) => {
  await gotoRoute(page, `/board/${boardKey}`);
  const app = page.frameLocator("iframe");
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await ensureOwner(page);

  await app.getByRole("button", { name: /Manage/ }).click();
  await app.getByRole("button", { name: /Board Settings/ }).click();
  const contact = "board@3x4g3um9JYXLchv5VE3SD8wW9TnR8oSMLAA7AYfodBFc";
  await app.locator("#board-contact-mail").fill(contact);
  await app.getByRole("button", { name: "Save contact" }).click();
  await waitForSync(page);
  await page.waitForTimeout(5_000);
  await app.getByRole("button", { name: "✕" }).click();

  await page.reload();
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await app.getByRole("button", { name: /Manage/ }).click();
  await app.getByRole("button", { name: /Board Settings/ }).click();
  await expect(app.locator("#board-contact-mail")).toHaveValue(contact);
});

test("an invited identity's first post survives a reload", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
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
  await expect(app.getByText(MAIN_BOARD).first()).toBeVisible({
    timeout: 30_000,
  });

  const title = `Guest membership test ${Date.now()}`;
  await app.getByRole("heading", { name: "General" }).click();
  await app.getByRole("button", { name: /New Topic/ }).first().click();
  await app.getByPlaceholder("Add a title...").fill(title);
  await app
    .locator("#message-input")
    .fill("Posted by the invited identity after joining.");
  const send = app.getByRole("button", { name: /Send Topic/ });
  await expect(send).toBeEnabled({ timeout: 60_000 });
  await send.click();
  try {
    await expect(
      app.getByText(title, { exact: true }).first(),
    ).toBeVisible({ timeout: 20_000 });
  } catch (error) {
    const body = await app.locator("body").innerText();
    console.log(
      "console errors before the first post disappeared:\n" +
        consoleErrors.slice(-20).join("\n") +
        "\n--- body ---\n" +
        body.slice(-1500),
    );
    throw error;
  }

  // Capture the exact guest profile row (nickname plus short id); many test
  // runs leave profiles with the same nickname.
  await waitForSync(page);
  await page.waitForTimeout(2_000);
  await app.getByRole("button", { name: "Open identities" }).click();
  const guestLabel = (
    await app
      .locator(".device-drawer .profile-row")
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
  await switchToProfile(page, OWNER);
  await page.reload();
  await page.goto(`${BASE}#/board/${boardKey}`);
  await app.getByText(MAIN_BOARD).first().waitFor({ timeout: 30_000 });
  await page.waitForTimeout(10_000);

  // Return to the invited identity and reload.
  await switchToProfile(page, guestId);
  await page.reload();
  await page.goto(`${BASE}#/board/${boardKey}`);
  await expect(
    app.getByText(title, { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
});
