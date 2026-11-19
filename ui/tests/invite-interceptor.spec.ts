import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("an invite link inside a message opens the join screen in place", async ({
  page,
}) => {
  await openBoard(page, "Team Chat Board");
  await page.getByText("Invite link", { exact: true }).first().click();
  await page.getByRole("link", { name: "Join the board" }).click();

  await expect(
    page.getByRole("heading", { name: "This invite link did not work" }),
  ).toBeVisible({ timeout: 10_000 });
});
