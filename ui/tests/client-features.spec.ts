import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("the client feature flag shows member IDs", async ({ page, isMobile }) => {
  await openBoard(page, "Team Chat Board");
  if (isMobile) {
    await page.getByRole("button", { name: "Menu" }).click();
  }
  await page.getByRole("button", { name: /Members/ }).click();
  await page.getByRole("button", { name: /FreeTalk Plaza/ }).click();

  const toggle = page.getByRole("checkbox", {
    name: "Show member IDs in the member list",
  });
  await expect(toggle).toBeVisible();
  await toggle.check();
  await page.getByRole("button", { name: "Close" }).click();

  if (isMobile) {
    await page.getByRole("button", { name: "Menu" }).click();
  }
  await page.getByRole("button", { name: /Members/ }).click();
  await expect(
    page.getByText(/· [1-9A-HJ-NP-Za-km-z]{4,8}/).first(),
  ).toBeVisible();

  await page.getByRole("button", { name: /FreeTalk Plaza/ }).click();
  await page
    .getByRole("checkbox", {
      name: "Show member IDs in the member list",
    })
    .uncheck();
  await page.getByRole("button", { name: "Close" }).click();
});
