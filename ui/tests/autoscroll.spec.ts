import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("a long topic opens pinned to the latest reply", async ({ page }) => {
  await openBoard(page, "Team Chat Board");
  await page.getByText("Autoscroll topic", { exact: true }).first().click();

  const scroll = page.locator("#message-scroll");
  await expect(scroll).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(400);

  const metrics = await scroll.evaluate((element) => ({
    top: element.scrollTop,
    max: element.scrollHeight - element.clientHeight,
  }));
  expect(metrics.max).toBeGreaterThan(200);
  expect(metrics.top).toBeGreaterThan(metrics.max - 12);
});
