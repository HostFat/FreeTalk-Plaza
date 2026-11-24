import { expect, test } from "@playwright/test";

// Topic-contract vertical slice against the local node. Run with:
//   $env:PLAZA_REAL_NODE_URL = "http://127.0.0.1:7509/v1/contract/web/<id>/index.html"
//   npx playwright test -c playwright.real-node.config.ts topics.spec.ts
const BASE = process.env.PLAZA_REAL_NODE_URL ?? "";
const RESET_KEY = "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB";
const BOARD_NAME = "TopicBoard";

function withTopics(url: string): string {
  const next = new URL(url);
  next.searchParams.set("topics", "1");
  next.searchParams.set("nav", Date.now().toString());
  return next.toString();
}

function withSections(url: string): string {
  const next = new URL(url);
  next.searchParams.set("topics", "1");
  next.searchParams.set("sections", "1");
  next.searchParams.set("nav", Date.now().toString());
  return next.toString();
}

async function appFrame(page: import("@playwright/test").Page) {
  const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
  if (!frame) throw new Error("The app iframe is not available");
  return frame;
}

async function waitForTopicRoute(
  page: import("@playwright/test").Page,
): Promise<string> {
  let topicId = "";
  await expect
    .poll(
      async () => {
        const hash = await (await appFrame(page)).evaluate(() => location.hash);
        const match = hash.match(
          /#\/board\/[^/]+\/topic\/([1-9A-HJ-NP-Za-km-z]+)/,
        );
        if (match) topicId = match[1];
        return Boolean(match);
      },
      { timeout: 60_000 },
    )
    .toBe(true);
  return topicId;
}

async function gotoRoot(page: import("@playwright/test").Page) {
  await page.goto(`${BASE}#/enable-topics`);
  await expect(
    page.frameLocator("iframe").getByText(/Select or Create Board/).first(),
  ).toBeVisible({ timeout: 30_000 });
}

async function createBoard(
  page: import("@playwright/test").Page,
  name = BOARD_NAME,
  nickname = "TopicOwner",
  privateBoard = false,
) {
  const app = page.frameLocator("iframe");
  const trigger = app
    .locator('div[role="button"]')
    .filter({
      has: app.getByText(
        /Select or Create Board|TopicBoard|PrivateTopics|MemberTopics|ApprovalBoard|BanBoard|PollBoard|StructureBoard|ContinueBoard|ReportBoard|SearchBoard/,
        { exact: true },
      ),
    })
    .first();
  await trigger.click();
  await app.getByRole("button", { name: "Create Board", exact: true }).click();
  await app.getByPlaceholder("Enter board name").fill(name);
  await app.getByPlaceholder("Enter your nickname").fill(nickname);
  if (privateBoard) {
    await app.getByRole("checkbox").first().check();
  }
  await app.getByRole("button", { name: "Create Board", exact: true }).click();

  let key = "";
  await expect
    .poll(
      async () => {
        const hash = await (await appFrame(page)).evaluate(() => location.hash);
        const match = hash.match(/#\/board\/([1-9A-HJ-NP-Za-km-z]+)/);
        if (match) key = match[1];
        return Boolean(match);
      },
      { timeout: 30_000 },
    )
    .toBe(true);
  await expect(app.getByText("New topic")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 60_000 });
  await page.waitForTimeout(4_000);
  return key;
}

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto(`${BASE}#/test-reset`);
  const app = page.frameLocator("iframe");
  const reset = app.getByRole("button", { name: "Reset local data" });
  await expect(reset).toBeVisible({ timeout: 30_000 });
  await reset.click();
  await page.waitForTimeout(3_000);
  await page.close();
});

test("a member joins a sectioned board and replies", async ({ page }) => {
  test.setTimeout(300_000);
  await page.goto(`${withSections(BASE)}#/enable-sections`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText(/Select or Create Board/).first()).toBeVisible({
    timeout: 30_000,
  });
  const suffix = Date.now().toString(36);
  const boardName = `MemberSectionBoard-${suffix}`;
  const ownerName = `MemberSectionOwner-${suffix}`;
  const memberName = `MemberSectionUser-${suffix}`;
  const boardKey = await createBoard(page, boardName, ownerName);

  await app.getByPlaceholder("New section name").fill("Member section");
  await app.getByRole("button", { name: "Create section" }).click();
  await expect(app.locator("option", { hasText: "Member section" })).toHaveCount(
    1,
    { timeout: 60_000 },
  );
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);
  await app.getByPlaceholder("Title").fill("Member section topic");
  await app.getByPlaceholder("Write the first message…").fill("Member section body");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(
    app.getByRole("heading", { name: "Member section topic" }),
  ).toBeVisible({ timeout: 60_000 });
  const topicId = await waitForTopicRoute(page);

  await page.goto(`${withSections(BASE)}#/board/${boardKey}/admin/roles`);
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByPlaceholder("New role name")).toHaveValue("", {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(`${withSections(BASE)}#/board/${boardKey}/admin/links`);
  await app.getByRole("button", { name: "Invite links" }).click();
  const role = app.getByRole("combobox").first();
  await expect(role.locator("option", { hasText: "Members" })).toHaveCount(1, {
    timeout: 30_000,
  });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const inviteLink = await link.inputValue();
  await page.waitForTimeout(3_000);

  await page.goto(inviteLink);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill(memberName);
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText(boardName).first()).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 60_000 });
  await page.waitForTimeout(6_000);

  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(
    app.getByRole("heading", { name: "Member section topic" }),
  ).toBeVisible({ timeout: 60_000 });
  await expect(app.getByPlaceholder("Write a reply…")).toBeVisible({
    timeout: 60_000,
  });
  await app.getByPlaceholder("Write a reply…").fill("Member section reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Member section reply")).toBeVisible({
    timeout: 60_000,
  });
});

test("a member joins a General section topic", async ({ page }) => {
  test.setTimeout(300_000);
  await page.goto(`${withSections(BASE)}#/enable-sections`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText(/Select or Create Board/).first()).toBeVisible({
    timeout: 30_000,
  });
  const suffix = Date.now().toString(36);
  const boardName = `GeneralMemberBoard-${suffix}`;
  const ownerName = `GeneralMemberOwner-${suffix}`;
  const memberName = `GeneralMemberUser-${suffix}`;
  const boardKey = await createBoard(page, boardName, ownerName);

  const generalOption = app.locator("option", { hasText: "General" }).first();
  await expect(generalOption).toHaveCount(1, { timeout: 30_000 });
  expect(await generalOption.getAttribute("data-contract")).toMatch(
    /^[1-9A-HJ-NP-Za-km-z]{43,44}$/,
  );

  await app.getByPlaceholder("Title").fill("General member topic");
  await app.getByPlaceholder("Write the first message…").fill("General body");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(
    app.getByRole("heading", { name: "General member topic" }),
  ).toBeVisible({ timeout: 60_000 });
  const topicId = await waitForTopicRoute(page);

  await page.goto(`${withSections(BASE)}#/board/${boardKey}/admin/roles`);
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByPlaceholder("New role name")).toHaveValue("", {
    timeout: 30_000,
  });
  await page.waitForTimeout(3_000);

  await page.goto(`${withSections(BASE)}#/board/${boardKey}/admin/links`);
  await app.getByRole("button", { name: "Invite links" }).click();
  const role = app.getByRole("combobox").first();
  await expect(role.locator("option", { hasText: "Members" })).toHaveCount(1, {
    timeout: 30_000,
  });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const inviteLink = await link.inputValue();
  await page.waitForTimeout(3_000);

  await page.goto(inviteLink);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill(memberName);
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText(boardName).first()).toBeVisible({
    timeout: 60_000,
  });
  await page.waitForTimeout(6_000);

  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(
    app.getByRole("heading", { name: "General member topic" }),
  ).toBeVisible({ timeout: 60_000 });
});

test("a sectioned board creates a child index contract", async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto(`${withSections(BASE)}#/enable-sections`);
  const app = page.frameLocator("iframe");
  await expect(app.getByText(/Select or Create Board/).first()).toBeVisible({
    timeout: 30_000,
  });
  const suffix = Date.now().toString(36);
  const boardKey = await createBoard(
    page,
    `SectionBoard-${suffix}`,
    `SectionOwner-${suffix}`,
  );

  await app.getByPlaceholder("New section name").fill("Shard section");
  await app.getByRole("button", { name: "Create section" }).click();
  const option = app.locator("option", { hasText: "Shard section" }).first();
  await expect(option).toHaveCount(1, { timeout: 60_000 });
  const contract = await option.getAttribute("data-contract");
  expect(contract, "the section must point to a child contract").toMatch(
    /^[1-9A-HJ-NP-Za-km-z]{43,44}$/,
  );

  // The topic and its activity live in the section child, not the parent.
  await app.getByPlaceholder("Title").fill("Section topic");
  await app.getByPlaceholder("Write the first message…").fill("Section body");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Section topic" })).toBeVisible({
    timeout: 60_000,
  });
  const topicId = await waitForTopicRoute(page);
  await app.getByPlaceholder("Write a reply…").fill("Section reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Section reply")).toBeVisible({ timeout: 60_000 });

  await page.goto(`${withSections(BASE)}#/board/${boardKey}`);
  await expect(app.getByText("Section topic")).toBeVisible({ timeout: 60_000 });
  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(app.getByText("Section reply")).toBeVisible({ timeout: 60_000 });

  await page.goto(`${withSections(BASE)}#/board/${boardKey}/search`);
  await app.getByPlaceholder("Search titles and previews").fill("Section topic");
  await expect(app.getByText("Section topic")).toBeVisible({ timeout: 30_000 });

  // Move the topic from Shard section to another section.
  await page.goto(`${withSections(BASE)}#/board/${boardKey}`);
  await app.getByPlaceholder("New section name").fill("Target section");
  await app.getByRole("button", { name: "Create section" }).click();
  await expect(app.locator("option", { hasText: "Target section" })).toHaveCount(
    1,
    { timeout: 60_000 },
  );
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);
  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  const moveSelect = app
    .locator("select")
    .filter({ has: app.locator("option", { hasText: "Target section" }) })
    .first();
  await moveSelect.selectOption({ label: "Target section" });
  await app.getByRole("button", { name: "Move", exact: true }).click();
  await page.waitForTimeout(4_000);
  await expect(
    app.locator("span", { hasText: "Target section" }).first(),
  ).toBeVisible({ timeout: 60_000 });
  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(
    app.locator("span", { hasText: "Target section" }).first(),
  ).toBeVisible({ timeout: 60_000 });

  // A second topic in Shard can merge into the moved topic in Target.
  await page.goto(`${withSections(BASE)}#/board/${boardKey}`);
  const sectionSelect = app.getByRole("combobox").first();
  await sectionSelect.selectOption({ label: "Shard section" });
  await app.getByPlaceholder("Title").fill("Merge source");
  await app.getByPlaceholder("Write the first message…").fill("Cross-section merge");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Merge source" })).toBeVisible({
    timeout: 60_000,
  });
  const mergeSourceId = await waitForTopicRoute(page);
  const mergeSelect = app
    .locator("select")
    .filter({ has: app.locator(`option[value="${topicId}"]`) })
    .first();
  await mergeSelect.selectOption(topicId);
  await app.getByRole("button", { name: "Merge", exact: true }).click();
  await page.waitForTimeout(4_000);
  await expect(app.getByText(/Merged into/)).toBeVisible({ timeout: 60_000 });
  await page.goto(
    `${withSections(BASE)}#/board/${boardKey}/topic/${mergeSourceId}`,
  );
  await expect(app.getByText(/Merged into/)).toBeVisible({ timeout: 60_000 });
});

test("a topic and its replies live in a separate contract", async ({ page }) => {
  test.setTimeout(240_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page);

  await app.getByPlaceholder("New section name").fill("Announcements");
  await app.getByRole("button", { name: "Create section" }).click();
  await expect(
    app.getByRole("option", { name: "Announcements" }),
  ).toHaveCount(1, { timeout: 30_000 });
  await app.getByRole("combobox").first().selectOption({ label: "Announcements" });

  await app.getByPlaceholder("Title").fill("Hello topics");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("The board keeps only the title and the index.");
  await app.getByRole("button", { name: "Create topic" }).click();

  await expect(app.getByText("Hello topics")).toBeVisible({ timeout: 60_000 });
  await expect(app.locator("span").filter({ hasText: "Announcements" }).first()).toBeVisible({ timeout: 30_000 });
  await expect(
    app.getByText("The board keeps only the title and the index."),
  ).toBeVisible({ timeout: 30_000 });

  const topicId = await waitForTopicRoute(page);

  await app.getByPlaceholder("Write a reply…").fill("First reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("First reply")).toBeVisible({ timeout: 60_000 });
  // Let the board activity hint reach the delegate and the network before the
  // page is reloaded.
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  // Reload the topic by id: the reply must come back from the topic contract.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Hello topics")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText("First reply")).toBeVisible({ timeout: 60_000 });

  // A reply draft is stored with the board and comes back after a reload.
  await app.getByPlaceholder("Write a reply…").fill("A draft that survives");
  await page.waitForTimeout(4_000);
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByPlaceholder("Write a reply…")).toHaveValue(
    "A draft that survives",
    { timeout: 60_000 },
  );

  // The board index shows the activity hint.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await expect(app.getByText("Hello topics")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText(/1 replies/)).toBeVisible({ timeout: 60_000 });

  // Author edits the topic and the reply; both survive a reload.
  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(app.getByText("Hello topics")).toBeVisible({ timeout: 60_000 });
  await app.getByRole("button", { name: "Edit topic", exact: true }).click();
  await app.getByPlaceholder("Topic title").fill("Hello topics edited");
  await app.getByPlaceholder("Topic body").fill("Edited topic body");
  await app.getByRole("button", { name: "Save topic", exact: true }).click();
  await expect(app.getByText("Hello topics edited")).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText("Edited topic body")).toBeVisible({
    timeout: 30_000,
  });

  await app.getByRole("button", { name: "Edit reply", exact: true }).click();
  await app.getByPlaceholder("Edit reply").fill("First reply edited");
  await app.getByRole("button", { name: "Save reply", exact: true }).click();
  await expect(app.getByText("First reply edited")).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(app.getByText("Hello topics edited")).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText("Edited topic body")).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText("First reply edited")).toBeVisible({
    timeout: 60_000,
  });

  // Owner moderation: pin and close are reflected in both contracts.
  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(app.getByText("Hello topics edited")).toBeVisible({
    timeout: 60_000,
  });
  await app.getByRole("button", { name: "Pin", exact: true }).click();
  await expect(app.getByText("Pinned")).toBeVisible({ timeout: 30_000 });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(2_000);
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await expect(app.getByText("Pinned")).toBeVisible({ timeout: 60_000 });

  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`,
  );
  await expect(app.getByText("Hello topics edited")).toBeVisible({
    timeout: 60_000,
  });
  await app.getByRole("button", { name: "Close", exact: true }).click();
  await expect(app.getByText("Closed")).toBeVisible({ timeout: 30_000 });
  await expect(app.getByPlaceholder("Write a reply…")).toHaveCount(0, {
    timeout: 30_000,
  });

  // Hide removes the topic from the index.
  await app.getByRole("button", { name: "Hide", exact: true }).click();
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await expect(app.getByText("Hello topics")).toHaveCount(0, {
    timeout: 60_000,
  });
});

test("a private topic keeps its text sealed", async ({ page }) => {
  test.setTimeout(240_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "PrivateTopics", "PrivateOwner", true);

  await app.getByPlaceholder("Title").fill("Sealed topic");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("This text must stay encrypted in the contract.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByText("Sealed topic")).toBeVisible({ timeout: 60_000 });

  const topicId = await waitForTopicRoute(page);

  await app.getByPlaceholder("Write a reply…").fill("Sealed reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Sealed reply")).toBeVisible({ timeout: 60_000 });

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Sealed topic")).toBeVisible({ timeout: 60_000 });
  await expect(
    app.getByText("This text must stay encrypted in the contract."),
  ).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText("Sealed reply")).toBeVisible({ timeout: 60_000 });
});

test("a board member can create a topic", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "MemberTopics", "MemberOwner");

  // A role is needed so the invite link has something to grant.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/roles`);
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByPlaceholder("New role name")).toHaveValue("", {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/links`);
  await app.getByRole("button", { name: "Invite links" }).click();
  const role = app.getByRole("combobox").first();
  await expect(role).toBeVisible({ timeout: 30_000 });
  await expect(role.locator("option", { hasText: "Members" })).toHaveCount(1, {
    timeout: 30_000,
  });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const inviteLink = await link.inputValue();
  await page.waitForTimeout(3_000);
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });

  await page.goto(inviteLink);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill("TopicMember");
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText("MemberTopics").first()).toBeVisible({
    timeout: 60_000,
  });

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await expect(app.getByText("New topic")).toBeVisible({ timeout: 60_000 });
  await app.getByPlaceholder("Title").fill("Member topic");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("Written by an invited member, not the owner.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByText("Member topic")).toBeVisible({ timeout: 60_000 });
  await expect(
    app.getByText("Written by an invited member, not the owner."),
  ).toBeVisible({ timeout: 60_000 });
});

test("the owner approves a pending reply", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const suffix = Date.now().toString(36);
  const boardName = `ApprovalBoard-${suffix}`;
  const ownerName = `ApprovalOwner-${suffix}`;
  const memberName = `ApprovalMember-${suffix}`;
  const boardKey = await createBoard(page, boardName, ownerName);

  // Turn the approval queue on before creating the topic, so the topic policy
  // carries approval_required.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/moderation`);
  await app.getByRole("button", { name: "Moderation" }).click();
  await app.getByRole("button", { name: "Approval queue is off" }).click();
  await expect(
    app.getByRole("button", { name: "Approval queue is on" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(2_000);

  // Create the role before the topic so the topic's authority snapshot knows
  // the role that the invite link will grant.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/roles`);
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByPlaceholder("New role name")).toHaveValue("", {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await app.getByPlaceholder("Title").fill("Approval topic");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("Only approved replies are visible.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByText("Approval topic")).toBeVisible({ timeout: 60_000 });
  const topicId = await waitForTopicRoute(page);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/links`);
  await app.getByRole("button", { name: "Invite links" }).click();
  const role = app.getByRole("combobox").first();
  await expect(role).toBeVisible({ timeout: 30_000 });
  await expect(role.locator("option", { hasText: "Members" })).toHaveCount(1, {
    timeout: 30_000,
  });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const inviteLink = await link.inputValue();
  await page.waitForTimeout(3_000);

  // The invited member posts a reply, which waits for approval. The same
  // client still holds the owner key, so it can approve from the same page.
  await page.goto(inviteLink);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill(memberName);
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText(boardName).first()).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 60_000 });
  await page.waitForTimeout(6_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Approval topic")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByPlaceholder("Write a reply…")).toBeVisible({
    timeout: 60_000,
  });
  await app.getByPlaceholder("Write a reply…").fill("Pending reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Pending reply")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText("Pending approval")).toBeVisible({
    timeout: 30_000,
  });

  await app
    .getByRole("button", { name: "Approve", exact: true })
    .last()
    .click();
  await expect(app.getByText("Pending approval")).toHaveCount(0, {
    timeout: 30_000,
  });
  await expect(app.getByText("Pending reply")).toBeVisible({ timeout: 30_000 });
});

test("a ban propagates to an existing topic", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const suffix = Date.now().toString(36);
  const boardName = `BanBoard-${suffix}`;
  const ownerName = `BanOwner-${suffix}`;
  const memberName = `BanMember-${suffix}`;
  const boardKey = await createBoard(page, boardName, ownerName);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/roles`);
  await app.getByRole("button", { name: "Roles", exact: true }).click();
  await app.getByPlaceholder("New role name").fill("Members");
  await app.getByRole("button", { name: "Create", exact: true }).click();
  await expect(app.getByPlaceholder("New role name")).toHaveValue("", {
    timeout: 30_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await app.getByPlaceholder("Title").fill("Ban topic");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("A topic that outlives its author's access.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByText("Ban topic")).toBeVisible({ timeout: 60_000 });
  const topicId = await waitForTopicRoute(page);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/links`);
  await app.getByRole("button", { name: "Invite links" }).click();
  const role = app.getByRole("combobox").first();
  await expect(role).toBeVisible({ timeout: 30_000 });
  await expect(role.locator("option", { hasText: "Members" })).toHaveCount(1, {
    timeout: 30_000,
  });
  await role.selectOption({ label: "Members" });
  await app.getByRole("button", { name: "Create link" }).click();
  const link = app.locator("input[readonly]").last();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const inviteLink = await link.inputValue();
  await page.waitForTimeout(3_000);

  await page.goto(inviteLink);
  await expect(
    app.getByRole("heading", { name: "Join this board" }),
  ).toBeVisible({ timeout: 30_000 });
  await app.getByPlaceholder("Your nickname").fill(memberName);
  await app.getByRole("button", { name: "Join" }).click();
  await expect(app.getByText(boardName).first()).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText("New topic")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 60_000 });
  await page.waitForTimeout(4_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Ban topic")).toBeVisible({ timeout: 60_000 });
  await app.getByPlaceholder("Write a reply…").fill("Before the ban");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Before the ban")).toBeVisible({ timeout: 60_000 });

  // Ban from the owner profile, then switch back to the member to verify the
  // propagated authority on the topic.
  await switchProfile(page, ownerName);
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/banned`);
  await app.getByRole("button", { name: "Banned", exact: true }).click();
  const memberSelect = app.getByRole("combobox").last();
  await expect(memberSelect).toBeVisible({ timeout: 30_000 });
  const memberOption = memberSelect
    .locator("option", { hasText: memberName })
    .first();
  const memberValue = await memberOption.getAttribute("value");
  await memberSelect.selectOption(memberValue!);
  await app.getByRole("button", { name: "Ban User", exact: true }).click();
  await app.getByRole("button", { name: "Yes, Ban User", exact: true }).click();
  await expect(app.getByText(/Banned Users/)).toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(10_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Banned author")).toBeVisible({ timeout: 60_000 });
});

async function switchProfile(
  page: import("@playwright/test").Page,
  name: string,
) {
  const app = page.frameLocator("iframe");
  if (!(await app.locator(".device-drawer").count())) {
    await app.getByRole("button", { name: "Open identities" }).click();
  }
  const drawer = app.locator(".device-drawer");
  await drawer.waitFor({ timeout: 15_000 });
  const row = drawer
    .locator(".profile-row")
    .filter({ has: app.getByText(name, { exact: true }) })
    .first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  const use = row.getByRole("button", { name: "Use on this board" });
  if (await use.count()) {
    await use.click();
    await expect(app.getByText("Identity switched.")).toBeVisible({
      timeout: 60_000,
    });
  }
  if (await drawer.count()) {
    await drawer.getByRole("button", { name: "Close" }).first().click().catch(() => {});
  }
}

test("reactions and polls survive a reload", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "PollBoard", "PollOwner");

  await app.getByPlaceholder("Title").fill("Poll and reactions");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("A topic with a reaction and a poll.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByText("Poll and reactions")).toBeVisible({
    timeout: 60_000,
  });
  const topicId = await waitForTopicRoute(page);

  // React to the topic header.
  await app.getByRole("button", { name: /👍/ }).first().click();
  await expect(app.getByRole("button", { name: /👍.*1/ })).toBeVisible({
    timeout: 30_000,
  });

  // Create a poll reply and vote on it.
  await app.getByRole("button", { name: "Poll", exact: true }).click();
  await app.getByPlaceholder("Poll question").fill("Best option?");
  await app.getByPlaceholder("Option 1").fill("Alpha");
  await app.getByPlaceholder("Option 2").fill("Beta");
  await app.getByRole("button", { name: "Create poll", exact: true }).click();
  await expect(app.getByText("Best option?")).toBeVisible({ timeout: 60_000 });
  await app.getByRole("button", { name: /Alpha/ }).click();
  await expect(app.getByRole("button", { name: /Alpha.*1/ })).toBeVisible({
    timeout: 30_000,
  });

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByRole("button", { name: /👍.*1/ })).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText("Best option?")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByRole("button", { name: /Alpha.*1/ })).toBeVisible({
    timeout: 60_000,
  });
});

test("move, merge and split keep the index consistent", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "StructureBoard", "StructureOwner");

  await app.getByPlaceholder("New section name").fill("News");
  await app.getByRole("button", { name: "Create section" }).click();
  await expect(app.getByRole("option", { name: "News" })).toHaveCount(1, {
    timeout: 30_000,
  });

  await app.getByPlaceholder("Title").fill("Move me");
  await app.getByPlaceholder("Write the first message…").fill("Source topic");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Move me", exact: true })).toBeVisible({ timeout: 60_000 });
  const moveHash = await (await appFrame(page)).evaluate(() => location.hash);
  const moveMatch = moveHash.match(/#\/board\/[^/]+\/topic\/([1-9A-HJ-NP-Za-km-z]+)/);
  expect(moveMatch).not.toBeNull();
  const moveTopicId = moveMatch![1];

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await app.getByPlaceholder("Title").fill("Destination");
  await app.getByPlaceholder("Write the first message…").fill("Destination topic");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Destination", exact: true })).toBeVisible({ timeout: 60_000 });
  const destHash = await (await appFrame(page)).evaluate(() => location.hash);
  const destMatch = destHash.match(
    /#\/board\/[^/]+\/topic\/([1-9A-HJ-NP-Za-km-z]+)/,
  );
  expect(destMatch).not.toBeNull();
  const destinationTopicId = destMatch![1];

  // Move the first topic to News from its owner controls.
  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${moveTopicId}`,
  );
  await expect(app.getByRole("heading", { name: "Move me", exact: true })).toBeVisible({ timeout: 60_000 });
  const moveSelect = app.locator("select").first();
  const newsValue = await moveSelect
    .locator("option", { hasText: "News" })
    .first()
    .getAttribute("value");
  await moveSelect.selectOption(newsValue!);
  await app.getByRole("button", { name: "Move", exact: true }).click();
  await expect(
    app.locator("span").filter({ hasText: "News" }).first(),
  ).toBeVisible({ timeout: 30_000 });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(6_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  const moveRow = app
    .locator("button")
    .filter({ has: app.getByText("Move me", { exact: true }) })
    .first();
  await expect(moveRow).toContainText("News", { timeout: 60_000 });

  // Merge the moved topic into Destination.
  await page.goto(
    `${withTopics(BASE)}#/board/${boardKey}/topic/${moveTopicId}`,
  );
  const mergeSelect = app
    .locator("select")
    .filter({ has: app.locator(`option[value="${destinationTopicId}"]`) })
    .first();
  await mergeSelect.selectOption(destinationTopicId);
  await app.getByRole("button", { name: "Merge", exact: true }).click();
  await expect(app.getByText(/Merged into/)).toBeVisible({ timeout: 30_000 });

  // Split a reply in Destination into a new topic.
  await page.goto(`${withTopics(BASE)}#/board/${boardKey}`);
  await app
    .locator("button")
    .filter({ has: app.getByText("Destination", { exact: true }) })
    .first()
    .click();
  await expect(app.getByText("Destination topic")).toBeVisible({ timeout: 60_000 });
  await app.getByPlaceholder("Write a reply…").fill("Reply to split");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Reply to split")).toBeVisible({ timeout: 60_000 });
  page.once("dialog", (dialog) => dialog.accept("Split topic"));
  await app.getByRole("button", { name: "Split", exact: true }).click();
  await expect(app.getByText("Split topic")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText("Reply to split")).toBeVisible({ timeout: 60_000 });
});

test("a long topic continues in a new part", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "ContinueBoard", "ContinueOwner");

  await app.getByPlaceholder("Title").fill("Long topic");
  await app.getByPlaceholder("Write the first message…").fill("First part");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Long topic" })).toBeVisible({
    timeout: 60_000,
  });
  const topicId = await waitForTopicRoute(page);

  await app.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(app.getByText("Part 2.")).toBeVisible({ timeout: 60_000 });
  await app.getByPlaceholder("Write a reply…").fill("Second part reply");
  await app.getByRole("button", { name: "Reply", exact: true }).click();
  await expect(app.getByText("Second part reply")).toBeVisible({
    timeout: 60_000,
  });
  await expect(app.getByText(/Syncing\./)).toHaveCount(0, { timeout: 30_000 });
  await page.waitForTimeout(3_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/topic/${topicId}`);
  await expect(app.getByText("Part 2.")).toBeVisible({ timeout: 60_000 });
  await expect(app.getByText("Second part reply")).toBeVisible({
    timeout: 60_000,
  });

  // The earlier part can be loaded read-only from the same topic page.
  await app.getByRole("button", { name: "Load earlier posts" }).click();
  await expect(app.getByRole("heading", { name: "Part 1", exact: true })).toBeVisible({
    timeout: 60_000,
  });
});

test("a topic report reaches the moderation queue", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "ReportBoard", "ReportOwner");

  await app.getByPlaceholder("Title").fill("Report me");
  await app.getByPlaceholder("Write the first message…").fill("Reportable topic");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Report me" })).toBeVisible({
    timeout: 60_000,
  });

  page.once("dialog", (dialog) => dialog.accept("Spam report"));
  await app.getByRole("button", { name: "Report", exact: true }).first().click();
  await page.waitForTimeout(3_000);

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/admin/moderation`);
  await app.getByRole("button", { name: "Moderation" }).click();
  await expect(app.getByText("Topic reports (1)")).toBeVisible({
    timeout: 30_000,
  });
  await expect(app.getByText("Spam report")).toBeVisible({ timeout: 30_000 });
  await app.getByRole("button", { name: "Resolve", exact: true }).click();
  await expect(app.getByText("Topic reports (0)")).toBeVisible({
    timeout: 30_000,
  });
});

test("the index search finds a topic by title and preview", async ({ page }) => {
  test.setTimeout(300_000);
  await gotoRoot(page);
  const app = page.frameLocator("iframe");
  const boardKey = await createBoard(page, "SearchBoard", "SearchOwner");

  await app.getByPlaceholder("Title").fill("Searchable title");
  await app
    .getByPlaceholder("Write the first message…")
    .fill("Preview needles are indexed too.");
  await app.getByRole("button", { name: "Create topic" }).click();
  await expect(app.getByRole("heading", { name: "Searchable title" })).toBeVisible({
    timeout: 60_000,
  });

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/search`);
  await app.getByPlaceholder("Search titles and previews").fill("Searchable");
  await expect(app.getByText("Searchable title")).toBeVisible({ timeout: 30_000 });
  await app.getByText("Searchable title").click();
  await expect(app.getByRole("heading", { name: "Searchable title" })).toBeVisible({
    timeout: 60_000,
  });

  await page.goto(`${withTopics(BASE)}#/board/${boardKey}/search`);
  await app.getByPlaceholder("Search titles and previews").fill("needles");
  await expect(app.getByText("Searchable title")).toBeVisible({ timeout: 30_000 });
});
