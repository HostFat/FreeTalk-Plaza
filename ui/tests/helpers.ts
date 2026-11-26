import { expect, Page } from "@playwright/test";

export async function openApp(page: Page) {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await expect(
    page.getByText("Select or Create Board", { exact: true }),
  ).toBeVisible({ timeout: 30_000 });
}

/** Open a board from the selector. The fixture board names are stable. */
export async function openBoard(page: Page, name: string) {
  await openApp(page);
  await page.getByText("Select or Create Board", { exact: true }).click();
  const item = page.getByRole("button", { name, exact: true });
  await expect(item).toBeVisible({ timeout: 10_000 });
  await item.click();
  await expect(page.getByText(name, { exact: true }).first()).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByText("Loading board…", { exact: true })).toHaveCount(0);
}

/** Open a board, select a section card, and ensure the New topic composer is ready. */
export async function openSectionComposer(
  page: Page,
  board: string,
  section: string,
) {
  await openBoard(page, board);
  const sectionCard = page
    .getByRole("button", { name: new RegExp(`^${section}\\b`) })
    .first();
  await expect(sectionCard).toBeVisible({ timeout: 10_000 });
  await sectionCard.click();
  await expect(page.locator("#topic-body-input")).toBeVisible({
    timeout: 10_000,
  });
}
