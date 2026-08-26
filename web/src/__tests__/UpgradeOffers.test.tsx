// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0020 §4, slice 5 — the non-blocking upgrade-offer panel. Two load-bearing properties:
// "no data to diff" (diff: null) must read differently from "diffed, no changes" (an empty
// diff), and accepting an offer must call the catalog-only re-pin route, never claim/register.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { UpgradeOffers } from "../components/UpgradeOffers";

const { upgrades, acceptUpgrade } = vi.hoisted(() => ({
  upgrades: vi.fn(),
  acceptUpgrade: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { catalog: { upgrades, acceptUpgrade } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const OFFER_WITH_DIFF = {
  hostname: "sensor-01",
  device_type_id: "t1",
  slug: "acme-x1",
  claimed_version: 1,
  current_version: 2,
  diff: { added: ["calibrate"], removed: [], changed: [], breaking: false, breaking_reasons: [] },
};

describe("UpgradeOffers", () => {
  beforeEach(() => {
    upgrades.mockReset();
    acceptUpgrade.mockReset();
  });

  it("renders nothing when there are no offers", async () => {
    upgrades.mockResolvedValue({ offers: [] });
    const { container } = render(<UpgradeOffers />);
    await waitFor(() => expect(upgrades).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the check itself fails, rather than nagging on a transient error", async () => {
    upgrades.mockRejectedValue(new Error("network down"));
    const { container } = render(<UpgradeOffers />);
    await waitFor(() => expect(upgrades).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the version bump and the declared tool diff", async () => {
    upgrades.mockResolvedValue({ offers: [OFFER_WITH_DIFF] });
    render(<UpgradeOffers />);
    expect(await screen.findByText(/sensor-01/)).toBeInTheDocument();
    expect(screen.getByText(/v1 → v2/)).toBeInTheDocument();
    expect(screen.getByText(/\+calibrate/)).toBeInTheDocument();
  });

  it("says the diff isn't available rather than 'no changes' when tool_set data is missing", async () => {
    upgrades.mockResolvedValue({ offers: [{ ...OFFER_WITH_DIFF, diff: null }] });
    render(<UpgradeOffers />);
    expect(await screen.findByText(/no declared tool set to compare/i)).toBeInTheDocument();
    expect(screen.queryByText(/no tool changes/i)).not.toBeInTheDocument();
  });

  it("says 'no tool changes' when diffed and genuinely nothing changed", async () => {
    upgrades.mockResolvedValue({
      offers: [
        {
          ...OFFER_WITH_DIFF,
          diff: { added: [], removed: [], changed: [], breaking: false, breaking_reasons: [] },
        },
      ],
    });
    render(<UpgradeOffers />);
    expect(await screen.findByText(/no tool changes/i)).toBeInTheDocument();
  });

  it("flags a breaking offer", async () => {
    upgrades.mockResolvedValue({
      offers: [{ ...OFFER_WITH_DIFF, diff: { ...OFFER_WITH_DIFF.diff, breaking: true } }],
    });
    render(<UpgradeOffers />);
    expect(await screen.findByText(/breaking change/i)).toBeInTheDocument();
  });

  it("accepting calls acceptUpgrade with the offer's hostname/type/current version and refreshes", async () => {
    upgrades.mockResolvedValueOnce({ offers: [OFFER_WITH_DIFF] }).mockResolvedValueOnce({ offers: [] });
    acceptUpgrade.mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(<UpgradeOffers />);
    await screen.findByText(/sensor-01/);

    await user.click(screen.getByRole("button", { name: /accept v2/i }));

    await waitFor(() => expect(acceptUpgrade).toHaveBeenCalledWith("sensor-01", "t1", 2));
    await waitFor(() => expect(upgrades).toHaveBeenCalledTimes(2)); // once on mount, once after accepting
  });
});
