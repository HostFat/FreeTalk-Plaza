import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("tapping a message reveals its actions on mobile", async ({
  page,
  isMobile,
}) => {
  test.skip(!isMobile, "touch-only behavior");
  await openBoard(page, "Your Private Board");
  await page.getByText("Reaction topic", { exact: true }).first().click();

  await page.getByRole("button", { name: "Message actions" }).first().tap();

  await expect(
    page.getByRole("button", { name: "delete", exact: true }).first(),
  ).toBeVisible({ timeout: 5_000 });
});
