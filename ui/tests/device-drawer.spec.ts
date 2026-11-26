import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("identities and backup live in the device drawer", async ({ page }) => {
  await openBoard(page, "Your Private Board");

  await page.getByRole("button", { name: "Open identities" }).click();
  const drawer = page.locator(".device-drawer");
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("tab", { name: "Identities" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(drawer.getByRole("tab", { name: "Mail" })).toBeVisible();
  await expect(drawer.getByText("Your identities")).toBeVisible();

  await drawer.getByRole("tab", { name: "Backup" }).click();
  await expect(drawer.getByLabel("Backup passphrase")).toBeVisible();
  await expect(drawer.getByLabel("Confirm passphrase")).toBeVisible();
  await expect(drawer.getByLabel("Restore passphrase")).toBeVisible();
  await expect(
    drawer.getByRole("button", { name: "Download backup" }),
  ).toBeVisible();
  await expect(
    drawer.getByRole("button", { name: "Restore now" }),
  ).toBeDisabled();
  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toHaveCount(0);

  // The footer opens About; About links to the same device drawer.
  await page.getByRole("button", { name: "About, build and backup" }).click();
  await expect(page.locator(".about-modal")).toBeVisible();
  await page.getByRole("button", { name: /Identities and backup/ }).click();
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("tab", { name: "Identities" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});
