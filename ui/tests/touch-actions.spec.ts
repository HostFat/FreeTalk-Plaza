import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("reply actions are directly reachable on mobile", async ({
  page,
  isMobile,
}) => {
  test.skip(!isMobile, "touch-only behavior");
  await openBoard(page, "Your Private Board");
  await page.getByText("Reaction topic", { exact: true }).first().click();

  await expect(
    page.getByRole("button", { name: "Delete", exact: true }).first(),
  ).toBeVisible({ timeout: 10_000 });
});
