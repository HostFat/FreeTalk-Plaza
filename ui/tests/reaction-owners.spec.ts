import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("tapping the reaction count opens the owner list", async ({ page }) => {
  await openBoard(page, "Your Private Board");
  await page.getByText("Reaction topic", { exact: true }).first().click();

  const count = page
    .locator(".reaction-chip")
    .filter({ hasText: "👍" })
    .locator(".reaction-count")
    .first();
  await expect(count).toBeVisible({ timeout: 10_000 });
  await count.click();

  const popover = page.locator(".reaction-owners-popover");
  await expect(popover).toBeVisible();
  await expect(popover.getByText(/reactions$/)).toBeVisible();
  await expect(popover.getByText("You", { exact: true })).toBeVisible();
  await popover.getByRole("button", { name: "Close" }).click();
  await expect(popover).toHaveCount(0);
});
