// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Export. The panel's whole job is the passphrase: the gateway mints it per export and keeps
// no copy, the BFF keeps no copy, and it is shown exactly once. An operator who does not
// capture it here holds an archive that nobody — including the gateway that made it — can ever
// open again. So the tests that matter are the ones about it staying on screen.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { BackupExport } from "../components/BackupExport";

const { prepareBackup, downloadBackupUrl } = vi.hoisted(() => ({
  prepareBackup: vi.fn(),
  downloadBackupUrl: vi.fn((t: string) => `/api/admin/backup/download?token=${t}`),
}));

vi.mock("../api", () => ({
  api: { prepareBackup, downloadBackupUrl },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const soon = (secs: number) => Date.now() / 1000 + secs;

const PREPARED = {
  download_token: "tok-abc",
  filename: "syncgate-backup-portable-20260817T230349Z.json",
  expires_at: soon(120),
  passphrase: "correct-horse-battery-staple-8821",
};

const prepareBtn = () => screen.getByRole("button", { name: /prepare export/i });

describe("BackupExport", () => {
  beforeEach(() => {
    prepareBackup.mockReset();
    prepareBackup.mockResolvedValue(PREPARED);
  });

  it("exports ciphertext by default and asks for no passphrase", async () => {
    // The safe, in-stack option is the one you get without choosing, and it has no passphrase
    // to lose.
    render(<BackupExport />);
    expect(screen.queryByLabelText("Archive passphrase")).not.toBeInTheDocument();
    await userEvent.setup().click(prepareBtn());
    await waitFor(() =>
      expect(prepareBackup).toHaveBeenCalledWith({ kind: "ciphertext", include_deadletters: false }),
    );
  });

  it("says a ciphertext archive is a credential dump too", async () => {
    // "Encrypted" reads as "safe to send". It is encrypted to this stack's key, which the
    // provider holds — so the warning is on screen before the export, not after.
    render(<BackupExport />);
    expect(screen.getByText(/complete copy of every credential/i)).toBeInTheDocument();
  });

  it("omits the passphrase key entirely when none was typed", async () => {
    // Omission is what tells a current gateway to mint one. Sending "" would read as a
    // supplied passphrase of zero length and be refused.
    render(<BackupExport />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: /portable/i }));
    await user.click(prepareBtn());
    await waitFor(() => expect(prepareBackup).toHaveBeenCalled());
    expect(prepareBackup.mock.calls[0][0]).not.toHaveProperty("passphrase");
  });

  it("sends a supplied passphrase for a portable archive", async () => {
    render(<BackupExport />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: /portable/i }));
    await user.type(screen.getByLabelText("Archive passphrase"), "my-own-passphrase-0123456789");
    await user.click(prepareBtn());
    await waitFor(() =>
      expect(prepareBackup).toHaveBeenCalledWith({
        kind: "portable",
        include_deadletters: false,
        passphrase: "my-own-passphrase-0123456789",
      }),
    );
  });

  it("reveals a minted passphrase and says it will not be shown again", async () => {
    render(<BackupExport />);
    await userEvent.setup().click(prepareBtn());
    expect(await screen.findByText(PREPARED.passphrase)).toBeInTheDocument();
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument();
  });

  it("keeps the passphrase on screen after the download", async () => {
    // The failure this prevents: the panel resets on download, and the only copy of the key
    // to the file the operator just saved disappears with it.
    render(<BackupExport />);
    const user = userEvent.setup();
    await user.click(prepareBtn());
    await user.click(await screen.findByRole("link", { name: /download/i }));
    expect(screen.getByText(PREPARED.passphrase)).toBeInTheDocument();
  });

  it("offers the download as a real link so the browser saves it", async () => {
    // Not a fetch: the response has to become a native download, which is the reason the whole
    // export is two steps rather than one.
    render(<BackupExport />);
    await userEvent.setup().click(prepareBtn());
    const link = await screen.findByRole("link", { name: /download/i });
    expect(link).toHaveAttribute("href", `/api/admin/backup/download?token=${PREPARED.download_token}`);
    expect(link).toHaveAttribute("download", PREPARED.filename);
  });

  it("says a prepared archive is served only once", async () => {
    render(<BackupExport />);
    const user = userEvent.setup();
    await user.click(prepareBtn());
    await user.click(await screen.findByRole("link", { name: /download/i }));
    expect(screen.getByText(/served once/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /download/i })).not.toBeInTheDocument();
  });

  it("shows no passphrase panel for an archive that has none", async () => {
    // A ciphertext export returns `passphrase: null`. An empty "copy this now" box would be a
    // standing instruction to capture nothing.
    prepareBackup.mockResolvedValue({ ...PREPARED, passphrase: null });
    render(<BackupExport />);
    await userEvent.setup().click(prepareBtn());
    await screen.findByRole("link", { name: /download/i });
    expect(screen.queryByText(/copy this passphrase now/i)).not.toBeInTheDocument();
  });

  it("says the file expired rather than leaving a dead link", async () => {
    prepareBackup.mockResolvedValue({ ...PREPARED, expires_at: soon(0) });
    render(<BackupExport />);
    await userEvent.setup().click(prepareBtn());
    expect(await screen.findByText(/expired before it was downloaded/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /download/i })).not.toBeInTheDocument();
    // The passphrase belonged to that archive and is now useless — said, not silently kept.
    expect(screen.getByText(/belongs to that expired archive/i)).toBeInTheDocument();
  });

  it("passes a refusal through in the gateway's own words", async () => {
    // An old gateway refuses a portable export with no passphrase; the message names exactly
    // that, and is more use than anything phrased here.
    const { ApiError } = await import("../api");
    prepareBackup.mockRejectedValue(new ApiError(409, "a portable export requires a passphrase"));
    render(<BackupExport />);
    await userEvent.setup().click(prepareBtn());
    expect(await screen.findByRole("alert")).toHaveTextContent(/requires a passphrase/);
  });
});
