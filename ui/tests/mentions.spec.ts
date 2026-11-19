import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test.describe("mentions", () => {
  test("the keyboard inserts the highlighted member without sending", async ({
    page,
  }) => {
    await openSectionComposer(page, "Team Chat Board", "General");

    const textarea = page.locator("#message-input");
    await textarea.fill("@");
    await expect(
      page.locator(".mention-autocomplete .mention-option").first(),
    ).toBeVisible({ timeout: 5_000 });
    await textarea.press("ArrowDown");
    await textarea.press("Enter");

    await expect(textarea).toHaveValue(/\]\(mention:/);
    await expect(page.getByPlaceholder("Add a title...")).toBeVisible();
  });

  test("autocomplete inserts a chip and clicking it opens the member", async ({
    page,
  }) => {
    await openSectionComposer(page, "Team Chat Board", "General");

    const textarea = page.locator("#message-input");
    await textarea.fill("@");

    const options = page.locator(".mention-autocomplete .mention-option");
    await expect(options.first()).toBeVisible({ timeout: 5_000 });
    const label = (await options.first().innerText()).trim();
    const name = label.replace(/^@/, "").trim();
    await options.first().click();

    await expect(textarea).toHaveValue(/\]\(mention:/);
    await page.getByPlaceholder("Add a title...").fill("Mention test");
    await textarea.press("End");
    await textarea.type(" hello");
    await page.getByRole("button", { name: /Send Topic/ }).click();

    const title = page.getByText("Mention test", { exact: true }).first();
    await expect(title).toBeVisible({ timeout: 10_000 });
    await title.click();

    const chip = page.locator(".plaza-mention").first();
    await expect(chip).toBeVisible({ timeout: 10_000 });
    await expect(chip).toContainText(`@${name}`);
    await chip.click();

    await expect(
      page.getByRole("heading", { name: "Member Info", exact: true }),
    ).toBeVisible({ timeout: 5_000 });
  });
});
