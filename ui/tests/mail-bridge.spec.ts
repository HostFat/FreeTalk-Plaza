import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("the device drawer stores a Freenet Mail address and links to the app", async ({
  page,
}) => {
  await openBoard(page, "Your Private Board");
  await page.getByRole("button", { name: "Open identities" }).click();
  const drawer = page.locator(".device-drawer");
  await drawer.getByRole("tab", { name: "Mail" }).click();

  await expect(
    drawer.getByRole("heading", { name: "Freenet Mail" }),
  ).toBeVisible();
  const address = "alice@123456789ABCDEFGHJKLMNPQRSTUVWXYZab";
  await page.locator("#mail-address").fill(address);
  await page.getByRole("button", { name: "Save address" }).click();
  await expect(page.locator("#mail-address")).toHaveValue(address);

  const open = drawer.getByRole("link", { name: /Open Freenet Mail/ });
  await expect(open).toHaveAttribute(
    "href",
    /122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC/,
  );
  await expect(
    drawer.getByRole("button", { name: "Hidden" }),
  ).toBeVisible();
  // The fixture board is public, so the publish option is Public. A private
  // board offers "Board members" instead.
  await expect(
    drawer.getByRole("button", { name: "Public", exact: true }),
  ).toBeVisible();
});
