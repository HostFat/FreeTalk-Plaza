import { expect, test } from "@playwright/test";
import { openBoard } from "./helpers";

test("an OS notification is created when permission is granted", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.__notifications = [];
    class FakeNotification {
      static permission = "granted";
      static requestPermission = async () => "granted";
      onclick: (() => void) | null = null;
      constructor(title: string, options?: { body?: string; tag?: string }) {
        window.__notifications.push({
          title,
          body: options?.body,
          tag: options?.tag,
        });
      }
      close() {}
    }
    (window as unknown as { Notification: typeof FakeNotification }).Notification =
      FakeNotification;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
  });

  await openBoard(page, "Team Chat Board");
  await page.waitForFunction(() => Boolean(window.__plazaTest));
  await page.evaluate(() =>
    window.__plazaTest.notify("Plaza test", "A new reply arrived"),
  );

  await expect
    .poll(() => page.evaluate(() => window.__notifications.length))
    .toBeGreaterThan(0);
  const notification = await page.evaluate(() => window.__notifications[0]);
  expect(notification.title).toBe("Plaza test");
  expect(notification.body).toBe("A new reply arrived");
});
