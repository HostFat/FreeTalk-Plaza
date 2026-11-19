import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test.describe("notification modes", () => {
  test("a board can be muted and restored from the notifications page", async ({
    page,
    isMobile,
  }) => {
    await openBoard(page, "Team Chat Board");
    if (isMobile) {
      await page.getByRole("button", { name: "Menu" }).click();
    }
    await page.getByRole("button", { name: /Notifications/ }).click();

    const mode = page.locator("#notification-mode");
    await expect(mode).toBeVisible();
    await mode.selectOption("muted");
    await expect(
      page.getByText("Notifications are muted for this board."),
    ).toBeVisible();

    await mode.selectOption("mentions");
    await expect(
      page.getByText("Notifications are muted for this board."),
    ).toHaveCount(0);

    await mode.selectOption("all");
    await expect(
      page.getByRole("heading", { name: "Notifications", exact: true }),
    ).toBeVisible();
  });
});
