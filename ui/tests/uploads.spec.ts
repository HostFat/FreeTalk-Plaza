import { expect, test } from "@playwright/test";
import { openSectionComposer } from "./helpers";

const PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

// The static example build has no blob contract, so the composer does not
// render the image picker. Keep the reproduction for a real-node run.
test.fixme("choosing an image adds an attachment to the composer", async ({
  page,
}) => {
  await openSectionComposer(page, "Team Chat Board", "General");
  await page.locator("#image-file-input").setInputFiles({
    name: "pixel.png",
    mimeType: "image/png",
    buffer: PIXEL_PNG,
  });

  await expect(page.getByText("pixel.png", { exact: false })).toBeVisible({
    timeout: 15_000,
  });
});
