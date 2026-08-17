// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Restore. The report shapes below are copied from real dry runs against the lab gateway —
// `skip` yields `skipped/"already registered"`, `overwrite` yields `would_restore`, `fail`
// yields `failed/"already registered (on_conflict=fail)"` — because the interesting assertion
// is that switching between them invalidates a plan, and that only means something if the
// plans genuinely differ.
//
// The load-bearing test is `withdraws Apply when an input changes after the preview`. A
// two-step confirm is theatre unless the thing confirmed is the thing that runs: preview with
// `skip`, switch to `overwrite`, apply, and every device is replaced by a plan nobody read.
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { BackupRestore } from "../components/BackupRestore";
import type { RestoreReport } from "../types";

const { restore } = vi.hoisted(() => ({ restore: vi.fn() }));

vi.mock("../api", () => ({
  api: { restore },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const ARCHIVE = '{"kind":"portable","version":1,"devices":[]}';

const skipReport: RestoreReport = {
  dry_run: true,
  kind: "portable",
  on_conflict: "skip",
  created_at: "2026-08-17T23:03:49.560685+00:00",
  counts: { skipped: 3 },
  fingerprint_warnings: 0,
  devices: [
    { hostname: "tlsprobe", outcome: "skipped", reason: "already registered" },
    { hostname: "prism", outcome: "skipped", reason: "already registered" },
    { hostname: "refmcp", outcome: "skipped", reason: "already registered" },
  ],
};

const overwriteReport: RestoreReport = {
  ...skipReport,
  on_conflict: "overwrite",
  counts: { would_restore: 3 },
  devices: skipReport.devices.map((d) => ({ hostname: d.hostname, outcome: "would_restore" })),
};

async function pasteArchive(user: ReturnType<typeof userEvent.setup>, text = ARCHIVE) {
  // `paste` rather than `type`: userEvent reads `[` and `{` as keyboard descriptors, and this
  // is how an operator supplies an archive anyway.
  await user.click(screen.getByRole("textbox", { name: /archive json/i }));
  await user.paste(text);
}

const previewBtn = () => screen.getByRole("button", { name: /^preview/i });
const applyBtn = () => screen.getByRole("button", { name: /apply this plan/i });

describe("BackupRestore", () => {
  beforeEach(() => {
    restore.mockReset();
    restore.mockResolvedValue(skipReport);
  });

  it("cannot apply before anything has been previewed", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    expect(applyBtn()).toBeDisabled();
    expect(screen.getByText(/a restore is never a guess/i)).toBeInTheDocument();
  });

  it("previews as a dry run and never as a write", async () => {
    // `dry_run` is passed explicitly at every layer rather than defaulted, so this pins the
    // one that a caller controls.
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(restore).toHaveBeenCalled());
    expect(restore.mock.calls[0][0]).toMatchObject({ dry_run: true, on_conflict: "skip" });
  });

  it("applies exactly the plan that was previewed", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());

    restore.mockResolvedValue({ ...skipReport, dry_run: false, counts: { restored: 3 } });
    await user.click(applyBtn());
    await waitFor(() => expect(restore).toHaveBeenCalledTimes(2));
    expect(restore.mock.calls[1][0]).toMatchObject({ dry_run: false, on_conflict: "skip" });
  });

  it("withdraws Apply when an input changes after the preview", async () => {
    // **The one that matters.** Every field is in the signature, so this covers the conflict
    // mode, the archive, the passphrase and the dead-letter flag alike.
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());

    await user.selectOptions(screen.getByRole("combobox"), "overwrite");
    expect(applyBtn()).toBeDisabled();
    expect(screen.getByText(/inputs changed since the preview/i)).toBeInTheDocument();
  });

  it("withdraws Apply when the archive itself is edited", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());

    await user.click(screen.getByRole("textbox", { name: /archive json/i }));
    await user.paste(" ");
    expect(applyBtn()).toBeDisabled();
  });

  it("withdraws Apply when the passphrase changes", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());

    await user.type(screen.getByLabelText(/passphrase/i), "x");
    expect(applyBtn()).toBeDisabled();
  });

  it("re-enables Apply once the changed inputs are previewed again", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());

    await user.selectOptions(screen.getByRole("combobox"), "overwrite");
    restore.mockResolvedValue(overwriteReport);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());
    // ...and the plan on screen is the new one, not the stale one it replaced.
    expect(screen.getByText(/would restore: 3/i)).toBeInTheDocument();
  });

  it("will not apply the same plan twice", async () => {
    // The report that comes back from a write has `dry_run: false`, which is not a plan any
    // more. Leaving Apply live would let a double click run the restore twice.
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    await waitFor(() => expect(applyBtn()).toBeEnabled());
    restore.mockResolvedValue({ ...skipReport, dry_run: false, counts: { restored: 3 } });
    await user.click(applyBtn());
    await waitFor(() => expect(applyBtn()).toBeDisabled());
    // ...and it says the plan was spent, not that the inputs changed. Nothing changed — and
    // the wrong sentence would send an operator hunting for an edit they never made.
    expect(await screen.findByText(/applied\. preview again/i)).toBeInTheDocument();
    expect(screen.queryByText(/inputs changed since the preview/i)).not.toBeInTheDocument();
  });

  it("shows each device's own outcome and reason, not just the counts", async () => {
    // "skipped because the hostname exists" and "failed because current policy would refuse
    // this registration" are different sentences, and only the per-device reason has them.
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    restore.mockResolvedValue({
      ...skipReport,
      counts: { skipped: 1, failed: 1 },
      devices: [
        { hostname: "tlsprobe", outcome: "skipped", reason: "already registered" },
        { hostname: "prism", outcome: "failed", reason: "base_url is not permitted by current policy" },
      ],
    });
    await user.click(previewBtn());

    const row = (await screen.findByText("prism")).closest("tr")!;
    expect(within(row).getByText(/failed/)).toBeInTheDocument();
    expect(within(row).getByText(/not permitted by current policy/)).toBeInTheDocument();
  });

  it("lifts fingerprint warnings out of the per-device list", async () => {
    // The gateway surfaces this at the top of its own report for the same reason: a pin
    // discarded on 3 of 500 devices is what gets missed during an incident.
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    restore.mockResolvedValue({
      ...overwriteReport,
      fingerprint_warnings: 2,
      devices: [
        { hostname: "tlsprobe", outcome: "would_restore", fingerprint_warning: "archived pin discarded" },
        { hostname: "prism", outcome: "would_restore", fingerprint_warning: "no pin; trust on first use" },
      ],
    });
    await user.click(previewBtn());
    expect(
      await screen.findByText(/2 devices would have their endpoint fingerprint changed/i),
    ).toBeInTheDocument();
  });

  it("refuses to send text that is not JSON, without calling the gateway", async () => {
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user, "not an archive");
    await user.click(previewBtn());
    expect(await screen.findByRole("alert")).toHaveTextContent(/not valid JSON/i);
    expect(restore).not.toHaveBeenCalled();
  });

  it("passes a refused restore through in the gateway's own words", async () => {
    // A wrong passphrase, a missing canary and a key mismatch all arrive as 409 with a
    // sentence naming which. Rewriting it costs the operator their only diagnostic.
    const { ApiError } = await import("../api");
    restore.mockRejectedValue(
      new ApiError(
        409,
        "could not open this portable archive — the passphrase is wrong (or the archive is corrupt)",
      ),
    );
    render(<BackupRestore />);
    const user = userEvent.setup();
    await pasteArchive(user);
    await user.click(previewBtn());
    expect(await screen.findByRole("alert")).toHaveTextContent(/passphrase is wrong/);
    // ...and a failed preview leaves nothing appliable behind.
    expect(applyBtn()).toBeDisabled();
  });
});
