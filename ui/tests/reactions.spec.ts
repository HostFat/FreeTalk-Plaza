import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test.describe("reactions", () => {
  test("hovering a reaction shows the reactor names", async ({
    page,
    isMobile,
  }) => {
    test.skip(isMobile, "the fixture reaction tooltip is hover-only");

    await openBoard(page, "Your Private Board");
    await page.getByText("Reaction topic", { exact: true }).first().click();
    await expect(page.getByText("Reaction topic", { exact: true })).toBeVisible();

    const chip = page.locator(".reaction-chip").first();
    await expect(chip).toBeVisible({ timeout: 10_000 });
    await chip.scrollIntoViewIfNeeded();
    await chip.hover();

    const tooltip = chip.locator(".reaction-tooltip");
    await expect(tooltip).toBeVisible();
    await expect(tooltip).not.toHaveText(/Unknown/);
  });
});
