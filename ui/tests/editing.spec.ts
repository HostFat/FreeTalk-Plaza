import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test("a member can edit and delete their own topic", async ({ page }) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.getByPlaceholder("Title", { exact: true }).fill("Edit delete test");
  await page.locator("#topic-body-input").fill("Original body");
  await page.getByRole("button", { name: "Create topic", exact: true }).click();

  await expect(page.getByText("Original body", { exact: true })).toBeVisible({
    timeout: 10_000,
  });
  await page.getByRole("button", { name: "Edit topic", exact: true }).click();

  const editor = page.getByPlaceholder("Topic body", { exact: true });
  await expect(editor).toBeVisible();
  await editor.fill("Edited body");
  await page.getByRole("button", { name: "Save topic", exact: true }).click();
  await expect(page.getByText("Edited body", { exact: true })).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.getByText("· edited", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Delete topic", exact: true }).click();
  await expect(page.getByText("Edit delete test", { exact: true })).toHaveCount(
    0,
    { timeout: 10_000 },
  );
});
