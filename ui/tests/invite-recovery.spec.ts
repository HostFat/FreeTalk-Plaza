import { expect, test } from "@playwright/test";

test.describe("damaged invite link", () => {
  test("offers a clear message and a paste field", async ({ page }) => {
    await page.goto("/#/join/not-a-valid-token", {
      waitUntil: "domcontentloaded",
    });

    await expect(
      page.getByRole("heading", { name: "This invite link did not work" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByText(/This invite link is incomplete or damaged/),
    ).toBeVisible();
    await expect(page.locator("#invite-recovery-input")).toBeVisible();
    await expect(page.getByRole("button", { name: "Open link" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Home" })).toBeVisible();
  });
});
