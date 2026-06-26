// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { deadLetters, replayDeadLetters, drainDeadLetters } = vi.hoisted(() => ({
  deadLetters: vi.fn(),
  replayDeadLetters: vi.fn(),
  drainDeadLetters: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { deadLetters, replayDeadLetters, drainDeadLetters },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

import { ApiError } from "../api";
import { DeadLetterPanel } from "../components/DeadLetterPanel";

const ENTRY = {
  id: "1700-0",
  reason: "execution_failed",
  ts: "1717500000",
  method: "tools/call",
  rid: "rid-1",
  request_id: "req-1",
  session_id: "sess-1",
};

describe("DeadLetterPanel", () => {
  beforeEach(() => {
    deadLetters.mockReset();
    replayDeadLetters.mockReset();
    drainDeadLetters.mockReset();
  });

  it("lists entries and replays a single entry (admin), then refreshes", async () => {
    deadLetters
      .mockResolvedValueOnce({ hostname: "dev", count: 1, entries: [ENTRY] })
      .mockResolvedValueOnce({ hostname: "dev", count: 0, entries: [] });
    replayDeadLetters.mockResolvedValue({ replayed: 1 });

    render(<DeadLetterPanel hostname="dev" canWrite={true} />);

    expect(await screen.findByText("tools/call")).toBeInTheDocument();
    expect(screen.getByText("execution_failed")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Replay" }));
    expect(replayDeadLetters).toHaveBeenCalledWith("dev", ["1700-0"]);
    // Refresh shows the now-empty queue + a notice.
    expect(await screen.findByText(/Replayed 1/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Empty.")).toBeInTheDocument());
  });

  it("hides mutating actions from viewers", async () => {
    deadLetters.mockResolvedValue({ hostname: "dev", count: 1, entries: [ENTRY] });
    render(<DeadLetterPanel hostname="dev" canWrite={false} />);

    expect(await screen.findByText("tools/call")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Replay" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Replay all" })).not.toBeInTheDocument();
  });

  it("renders the distributed-mode-only note on a 400", async () => {
    deadLetters.mockRejectedValue(
      new ApiError(400, "Dead-letter queue is only available in distributed mode"),
    );
    render(<DeadLetterPanel hostname="dev" canWrite={true} />);

    expect(await screen.findByText(/Available in distributed mode only/)).toBeInTheDocument();
  });
});
