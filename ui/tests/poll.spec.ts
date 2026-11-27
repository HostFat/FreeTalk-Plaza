import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test("a poll can be created, voted, and edited", async ({ page }) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.getByPlaceholder("Title", { exact: true }).fill("Poll test");
  await page.locator("#topic-body-input").fill("Vote on the options below");
  await page.getByRole("button", { name: "Create topic", exact: true }).click();

  await expect(
    page.getByRole("heading", { name: "Poll test", exact: true }),
  ).toBeVisible({ timeout: 10_000 });

  await page.getByRole("button", { name: "Poll", exact: true }).click();
  await page.getByPlaceholder("Poll question", { exact: true }).fill("Pick one");
  await page.getByPlaceholder("Option 1", { exact: true }).fill("Alpha");
  await page.getByPlaceholder("Option 2", { exact: true }).fill("Beta");
  await page.getByRole("button", { name: "Create poll", exact: true }).click();

  await page.getByRole("button", { name: /Alpha/ }).click();
  await expect(page.getByText("Vote recorded.", { exact: false })).toBeVisible({
    timeout: 10_000,
  });

  // The author can still edit the options after a vote.
  await page.getByRole("button", { name: "Edit poll", exact: true }).click();
  const opt1 = page.getByPlaceholder("Option 1", { exact: true });
  await expect(opt1).toBeVisible({ timeout: 10_000 });
  await opt1.fill("Gamma");
  await page.getByRole("button", { name: "Save poll", exact: true }).click();
  await expect(page.getByText("Gamma", { exact: false })).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.getByText("· edited", { exact: false }).first()).toBeVisible();
});
