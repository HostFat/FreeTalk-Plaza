import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test.describe("owner controls follow the visible profile", () => {
  test("the owner profile shows the crown and Manage", async ({
    page,
    isMobile,
  }) => {
    await openBoard(page, "Your Private Board");

    await expect(page.getByTitle("Board Owner")).toBeVisible();
    if (isMobile) {
      // The narrow top bar keeps Manage behind its own menu; the crown is the
      // identity signal these tests care about.
      return;
    }
    await expect(page.getByRole("button", { name: /Manage/ })).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Create section", exact: true }),
    ).toBeVisible();
  });

  test("a member profile does not inherit owner controls", async ({ page }) => {
    await openBoard(page, "Team Chat Board");

    await expect(page.getByTitle("Board Owner")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Manage/ })).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Create section", exact: true }),
    ).toHaveCount(0);
  });

  test("a retained owner key on a member profile stays hidden", async ({
    page,
  }) => {
    await openBoard(page, "Owner Key, Member Profile");

    await expect(page.getByTitle("Board Owner")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Manage/ })).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Create section", exact: true }),
    ).toHaveCount(0);
  });
});
