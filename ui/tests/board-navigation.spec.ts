import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

const BOARDS = [
  "Public Discussion Board",
  "Team Chat Board",
  "Your Private Board",
  "Owner Key, Member Profile",
];

test.describe("board selection", () => {
  for (const name of BOARDS) {
    test(`${name} opens instead of staying on Loading board`, async ({
      page,
    }) => {
      await openBoard(page, name);

      await expect(page).toHaveURL(/\/#\/board\//);
      await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
      await expect(page.getByText("Loading board…", { exact: true })).toHaveCount(0);
    });
  }

  test("the selector lists every fixture board", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByText("Select or Create Board", { exact: true }).click();

    for (const name of BOARDS) {
      await expect(page.getByRole("button", { name, exact: true })).toBeVisible();
    }
  });
});
