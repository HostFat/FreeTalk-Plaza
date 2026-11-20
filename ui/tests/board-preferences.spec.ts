import { expect, test, Page } from "@playwright/test";
import { openApp, openBoard } from "./helpers";

async function boardNames(page: Page): Promise<[string, boolean][]> {
  await page.waitForFunction(() => Boolean(window.__plazaTest), null, {
    timeout: 10_000,
  });
  return page.evaluate(() => window.__plazaTest.boardNames());
}

test.describe("board list preferences", () => {
  test("the arrow buttons reorder the visible boards", async ({ page }) => {
    await openApp(page);
    const before = (await boardNames(page)).filter(([, archived]) => !archived);
    expect(before.length).toBeGreaterThan(1);

    await page.getByText("Select or Create Board", { exact: true }).click();
    const row = page
      .locator("div.w-full.flex.items-center.gap-2")
      .filter({ hasText: before[1][0] });
    await row.getByTitle("Move board up").click();

    const after = (await boardNames(page)).filter(([, archived]) => !archived);
    expect(after[0][0]).toBe(before[1][0]);
    expect(after[1][0]).toBe(before[0][0]);
  });

  test("a board can be archived and restored", async ({ page }) => {
    await openApp(page);
    const target = (await boardNames(page))[0][0];
    await page.getByText("Select or Create Board", { exact: true }).click();

    let row = page
      .locator("div.w-full.flex.items-center.gap-2")
      .filter({ hasText: target });
    await row.getByTitle("Archive board").click();
    await expect(page.getByText("Archived", { exact: true })).toBeVisible();

    let state = await boardNames(page);
    expect(state.find(([name]) => name === target)?.[1]).toBe(true);

    row = page
      .locator("div.w-full.flex.items-center.gap-2")
      .filter({ hasText: target });
    await row.getByTitle("Restore board").click();
    state = await boardNames(page);
    expect(state.find(([name]) => name === target)?.[1]).toBe(false);
  });

  test("the switcher shows a loading state before the delegate loads", async ({
    page,
  }) => {
    await openApp(page);
    await page.evaluate(() => window.__plazaTest.clearBoards());
    await expect(
      page.getByText("Select or Create Board", { exact: true }),
    ).toBeVisible({ timeout: 5_000 });
    await page.getByText("Select or Create Board", { exact: true }).click();
    await expect(page.getByText("Loading boards…")).toBeVisible();
  });

  test("a private board without a key shows the recovery screen", async ({
    page,
  }) => {
    await openBoard(page, "Missing Key Board");
    await expect(
      page.getByText("Board key missing", { exact: true }),
    ).toBeVisible();
  });
});
