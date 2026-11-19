import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

test.describe("section auto-moderation policy", () => {
  test("a General section inheriting the board shows the checkbox unchecked", async ({
    page,
  }) => {
    await openSectionComposer(page, "Team Chat Board", "General");

    const checkbox = page.getByRole("checkbox", { name: "Moderate replies" });
    await expect(checkbox).toBeVisible();
    await expect(checkbox).not.toBeChecked();
  });

  test("a section with the policy off has no checkbox", async ({ page }) => {
    await openSectionComposer(page, "Team Chat Board", "NoAuto");

    await expect(
      page.getByRole("checkbox", { name: "Moderate replies" }),
    ).toHaveCount(0);
  });
});
