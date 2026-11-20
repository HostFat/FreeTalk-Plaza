import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test("a member can edit and delete their own topic", async ({ page }) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.getByPlaceholder("Add a title...").fill("Edit delete test");
  await page.locator("#message-input").fill("Original body");
  await page.getByRole("button", { name: /Send Topic/ }).click();

  await page.getByText("Edit delete test", { exact: true }).first().click();
  const body = page.getByText("Original body", { exact: true }).first();
  await expect(body).toBeVisible({ timeout: 10_000 });
  await body.hover();
  await page
    .getByRole("button", { name: "edit", exact: true })
    .first()
    .dispatchEvent("click");

  const editor = page.locator("#edit-message-input");
  await expect(editor).toBeVisible();
  await editor.fill("Edited body");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Edited body", { exact: true })).toBeVisible({
    timeout: 10_000,
  });

  await page.getByText("Edited body", { exact: true }).first().hover();
  const deleteButton = page
    .getByRole("button", { name: "delete", exact: true })
    .first();
  await expect(deleteButton).toBeVisible({ timeout: 5_000 });
  await deleteButton.dispatchEvent("click");
  await expect(
    page.getByRole("heading", { name: "Delete topic permanently?" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Delete permanently" }).click();

  await expect(page.getByText("Edited body", { exact: true })).toHaveCount(0, {
    timeout: 10_000,
  });
});

test.fixme("deleting a reply lowers the topic reply count", async ({ page }) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.getByPlaceholder("Add a title...").fill("Reply count test");
  await page.locator("#message-input").fill("Root post");
  await page.getByRole("button", { name: /Send Topic/ }).click();

  await page.getByText("Reply count test", { exact: true }).first().click();
  await page.getByRole("button", { name: /Compose Reply/ }).click();
  await page.locator("#message-input").fill("Reply to delete");
  await page.getByRole("button", { name: /Send Reply/ }).click();
  await expect(page.getByText("Reply to delete", { exact: true })).toBeVisible({
    timeout: 10_000,
  });

  await page.getByRole("button", { name: /Back to topics/ }).click();
  await expect(
    page.getByText("1 reply", { exact: false }).first(),
  ).toBeVisible();

  await page.getByText("Reply count test", { exact: true }).first().click();
  await page.getByText("Reply to delete", { exact: true }).hover();
  await page
    .getByRole("button", { name: "delete", exact: true })
    .first()
    .dispatchEvent("click");
  await page.getByRole("button", { name: "Delete", exact: true }).click();

  await page.getByRole("button", { name: /Back to topics/ }).click();
  await expect(
    page.getByText("0 replies", { exact: false }).first(),
  ).toBeVisible({ timeout: 10_000 });
});
