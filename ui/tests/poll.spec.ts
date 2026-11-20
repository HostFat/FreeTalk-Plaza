import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test("a poll can be created and voted", async ({ page }) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.getByPlaceholder("Add a title...").fill("Poll test");
  await page.getByRole("button", { name: "Poll", exact: true }).click();
  await page.getByPlaceholder("Option 1").fill("Alpha");
  await page.getByPlaceholder("Option 2").fill("Beta");
  await page.getByRole("button", { name: /Send Topic/ }).click();

  await page.getByText("Poll test", { exact: true }).first().click();
  await page.getByRole("button", { name: /Alpha/ }).click();
  await page.getByRole("button", { name: "Vote", exact: true }).click();

  await expect(page.getByText("Vote recorded.", { exact: false })).toBeVisible({
    timeout: 10_000,
  });
});
