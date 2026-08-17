// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The provider plane through a browser (ADR-0013 §4/§8). Every route below was already
// covered on the BFF side; what is untested until here is whether an operator can *see*
// the three properties the design turns on — that acting on a tenant is a discrete,
// justified act, that only one is held at a time, and that a single-use elevation is a
// visibly different thing from an invoke one.
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ProviderConsole } from "../components/ProviderConsole";
import { readStepUpOutcome } from "../stepUpOutcome";
import type { AuthConfig, Session } from "../types";

const { authorize, actOnTenant, release, elevate, elevation, endElevation, overview } = vi.hoisted(() => ({
  overview: vi.fn(),
  authorize: vi.fn(),
  actOnTenant: vi.fn(),
  release: vi.fn(),
  elevate: vi.fn(),
  elevation: vi.fn(),
  endElevation: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { provider: { authorize, actOnTenant, release, elevate, elevation, endElevation }, overview },
  asGrant: (r: unknown) => (r && "grant" in (r as object) ? null : r),
  asElevation: (r: unknown) => (r && "elevation" in (r as object) ? null : r),
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const SESSION: Session = {
  kind: "oidc",
  plane: "provider",
  subject: "op-14",
  role: null,
  scopes: [],
  provider_scopes: ["provider:admin"],
  name: "Sam Okafor",
};

const CONFIG: AuthConfig = {
  oidc_enabled: false,
  password_login: true,
  provider_enabled: true,
  step_up_enabled: true,
};

const soon = (secs: number) => Date.now() / 1000 + secs;

/** Text of the panel containing `match`.
 *
 * A countdown renders as several text nodes — a label and a value — so `getByText` cannot
 * match it as one string, and asserting the exact remaining second is a race. Reading the
 * whole panel tests what a reader actually sees.
 */
function panelText(match: RegExp): string {
  return screen.getByText(match).closest("section")?.textContent ?? "";
}

/** Text of the persistent act bar. It lives in the shell rather than a panel (W3), so it has
 *  no enclosing <section> — walk to the flex row that holds the countdown instead. */
function barText(): string {
  return screen.getByText(/acting on/i).parentElement?.textContent ?? "";
}

function renderConsole(config: AuthConfig = CONFIG) {
  return render(<ProviderConsole session={SESSION} config={config} onSignOut={vi.fn()} />);
}

// jsdom's `location` reads its fields from getters, so spreading it produces a detached
// snapshot: once assigned over `window.location`, `history.replaceState` no longer moves
// `search`, and every later test that reads the URL sees a frozen one. Restore the real
// object after each test rather than leaving one test's stub to poison the rest.
const REAL_LOCATION = window.location;

describe("ProviderConsole", () => {
  beforeEach(() => {
    for (const fn of [authorize, actOnTenant, release, elevate, elevation, endElevation, overview])
      fn.mockReset();
    overview.mockResolvedValue({ devices: [], counts: {} });
    actOnTenant.mockResolvedValue({ grant: null });
    elevation.mockResolvedValue({ elevation: null });
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    Object.defineProperty(window, "location", {
      value: REAL_LOCATION,
      writable: true,
      configurable: true,
    });
  });

  it("says plainly that signing in reaches no tenant", async () => {
    renderConsole();
    expect(await screen.findByText(/not acting on any tenant/i)).toBeInTheDocument();
  });

  it("refuses to authorize without a justification", async () => {
    renderConsole();
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText("tenant id"), "acme");
    // The justification is unrecoverable — it goes into an append-only chain and is never
    // echoed back — so this is the only moment it can be written, and the button must not
    // let an operator past it.
    expect(screen.getByRole("button", { name: /^authorize$/i })).toBeDisabled();
    await user.type(screen.getByPlaceholderText(/ticket, incident/i), "INC-4471");
    expect(screen.getByRole("button", { name: /^authorize$/i })).toBeEnabled();
  });

  it("sends the tenant and justification, then shows the live act with a countdown", async () => {
    authorize.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText("tenant id"), "acme");
    await user.type(screen.getByPlaceholderText(/ticket, incident/i), "INC-4471");

    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    await user.click(screen.getByRole("button", { name: /^authorize$/i }));

    expect(authorize).toHaveBeenCalledWith("acme", "INC-4471");
    expect(await screen.findByText(/acting on/i)).toHaveTextContent("acme");
    await waitFor(() => expect(barText()).toMatch(/ends in \d+:\d\d/));
  });

  it("warns that authorizing another tenant ends the current act", async () => {
    // §8 holds one grant per session: the second authorize drops the first. An operator
    // who cannot see that discovers it by finding themselves detached from the tenant they
    // were working on.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText("tenant id"), "globex");
    expect(await screen.findByText(/this ends the current act on/i)).toHaveTextContent("acme");
    expect(screen.getByRole("button", { name: /replaces current act/i })).toBeInTheDocument();
  });

  it("offers no elevation until a tenant is being acted on", async () => {
    renderConsole();
    expect(await screen.findByText(/authorize an act on a tenant first/i)).toBeInTheDocument();
  });

  it("hides elevation entirely when the deployment cannot verify a step-up", async () => {
    // Not "broken" — not offered. A console that showed the button here would walk an
    // operator through a second factor to reach a 404.
    renderConsole({ ...CONFIG, step_up_enabled: false });
    expect(await screen.findByText(/no step-up context is configured/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /step up/i })).not.toBeInTheDocument();
  });

  it("leaves for the IdP rather than treating the click as authority", async () => {
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    elevate.mockResolvedValue({ authorization_url: "https://idp.example/authorize?state=x" });
    const assign = vi.fn();
    // Built field by field rather than spread, for the reason above.
    Object.defineProperty(window, "location", {
      value: { href: "/", pathname: "/", search: "", assign },
      writable: true,
      configurable: true,
    });

    renderConsole();
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText(/what you are about to do/i), "reproducing the fault");
    await user.click(screen.getByRole("button", { name: /step up and elevate/i }));

    expect(elevate).toHaveBeenCalledWith("acme", "provider:invoke", "reproducing the fault");
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://idp.example/authorize?state=x"));
    // Nothing about the UI may claim an elevation was obtained by clicking.
    expect(screen.queryByText(/expires in/i)).not.toBeInTheDocument();
  });

  it("shows a single-use elevation as a state, not a footnote", async () => {
    // The two classes differ at the moment they are used. Rendering both as "elevated
    // until 12:04" would describe the credentials grant wrongly — its holder is one
    // operation away from having nothing.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    elevation.mockResolvedValue({
      id: "e1",
      tenant: "acme",
      scope: "provider:credentials",
      granted_at: soon(0),
      expires_at: soon(300),
      single_use: true,
    });
    renderConsole();
    expect(await screen.findByText(/single use/i)).toBeInTheDocument();
    await waitFor(() => expect(panelText(/single use/i)).toMatch(/expires in \d+:\d\d/));
  });

  it("describes an invoke elevation as lasting its window", async () => {
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    elevation.mockResolvedValue({
      id: "e2",
      tenant: "acme",
      scope: "provider:invoke",
      granted_at: soon(0),
      expires_at: soon(900),
      single_use: false,
    });
    renderConsole();
    expect(await screen.findByText(/usable for the rest of this window/i)).toBeInTheDocument();
    expect(screen.queryByText(/single use/i)).not.toBeInTheDocument();
  });

  it("names a declined step-up as itself", async () => {
    // The case a real IdP produces: a valid sign-in with the step-up not performed. The
    // difference between "try again" and "your directory is not enforcing the second
    // factor you configured" is the whole value of surfacing it.
    window.history.replaceState({}, "", "/?elevation=denied&reason=step_up_declined");
    renderConsole();
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(/did not perform the step-up/i)).toBeInTheDocument();
  });

  it("names an IdP refusal as a config fault, not a broken callback", async () => {
    // The regression that a real Keycloak found: an unattached client scope came back as
    // "the step-up came back incomplete", sending the reader at the transport instead of
    // at the directory configuration that was actually wrong.
    window.history.replaceState({}, "", "/?elevation=denied&reason=idp_refused");
    renderConsole();
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(/identity provider refused the request/i)).toBeInTheDocument();
    expect(within(alert).queryByText(/came back incomplete/i)).not.toBeInTheDocument();
  });

  it("strips the outcome from the URL once it has been read", async () => {
    // It must not survive a reload or be bookmarked — and a stale "granted" beside an
    // elevation that has since been spent would be the console lying about live authority.
    window.history.replaceState({}, "", "/?elevation=granted");
    renderConsole();
    await waitFor(() => expect(window.location.search).toBe(""));
  });

  it("tells an operator whose groups map to nothing, rather than 403ing everywhere", async () => {
    render(
      <ProviderConsole session={{ ...SESSION, provider_scopes: [] }} config={CONFIG} onSignOut={vi.fn()} />,
    );
    expect(await screen.findByText(/grant no provider access/i)).toBeInTheDocument();
  });
});

describe("readStepUpOutcome", () => {
  it("reads the closed vocabulary the BFF redirects with", () => {
    expect(readStepUpOutcome("?elevation=granted")).toEqual({ status: "granted" });
    expect(readStepUpOutcome("?elevation=denied&reason=step_up_declined")).toEqual({
      status: "denied",
      reason: "step_up_declined",
    });
  });

  it("is null for an ordinary load, so nothing is announced without a step-up", () => {
    expect(readStepUpOutcome("")).toBeNull();
    expect(readStepUpOutcome("?tab=devices")).toBeNull();
  });
});

describe("the tenant's fleet, reached through the act (W1)", () => {
  beforeEach(() => {
    for (const fn of [actOnTenant, elevation, overview]) fn.mockReset();
    elevation.mockResolvedValue({ elevation: null });
    overview.mockResolvedValue({ devices: [], counts: {} });
    window.history.replaceState({}, "", "/");
  });

  it("shows nothing of the fleet before an act exists", async () => {
    // Tier 0 reaches no customer stack at all. A fleet request here would 403 every time,
    // and showing an empty list would imply the tenant has no devices rather than that we
    // have no authority to look.
    actOnTenant.mockResolvedValue({ grant: null });
    renderConsole();
    await screen.findByText(/not acting on any tenant/i);
    expect(overview).not.toHaveBeenCalled();
  });

  it("loads the acted-on tenant's devices once an act is live", async () => {
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await waitFor(() => expect(overview).toHaveBeenCalled());
    expect(await screen.findByRole("heading", { name: "acme" })).toBeInTheDocument();
  });

  it("names whose estate is on screen", async () => {
    // D3, partially: an operator several screens into a device list should not have to
    // remember which customer's hardware they are looking at.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    expect(await screen.findByText(/everything below is that customer/i)).toBeInTheDocument();
  });

  it("withholds write affordances while D2 is open", async () => {
    // devices:write is inside the gateway ceiling, so this is the console declining rather
    // than the gateway refusing. A ceiling is what the plane may do; a console is what we
    // put a button on.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await screen.findByRole("heading", { name: "acme" });
    expect(screen.queryByRole("button", { name: /delete|register device/i })).not.toBeInTheDocument();
  });

  it("offers monitoring at the same tier as the device list (W2)", async () => {
    // metrics:read is already inside the provider ceiling, so monitoring needs no elevation.
    // If this ever required a step-up, the tier model would have drifted.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    expect(await screen.findByRole("button", { name: /monitoring/i })).toBeEnabled();
  });
});
