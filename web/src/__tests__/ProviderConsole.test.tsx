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

const {
  authorize,
  actOnTenant,
  release,
  elevate,
  elevation,
  endElevation,
  overview,
  tenants,
  diagnostics,
  getDevice,
  tools,
  toolsDiff,
  deadLetters,
} = vi.hoisted(() => ({
  overview: vi.fn(),
  tenants: vi.fn(),
  authorize: vi.fn(),
  actOnTenant: vi.fn(),
  release: vi.fn(),
  elevate: vi.fn(),
  elevation: vi.fn(),
  endElevation: vi.fn(),
  // DeviceDetail's own reads, needed only by the invoke-gating tests at the end.
  diagnostics: vi.fn(),
  getDevice: vi.fn(),
  tools: vi.fn(),
  toolsDiff: vi.fn(),
  deadLetters: vi.fn(),
}));

vi.mock("../api", () => ({
  api: {
    provider: { authorize, actOnTenant, release, elevate, elevation, endElevation, tenants },
    overview,
    diagnostics,
    getDevice,
    tools,
    toolsDiff,
    deadLetters,
  },
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

/** Text of the status strip — the shell's persistent footer, which owns the live grant. */
function stripText(): string {
  return document.querySelector("footer")?.textContent ?? "";
}

/** Navigate the rail the way an operator does. Tier-1 views are not on the landing screen;
 *  reaching them is the act being spent, which is the behaviour worth testing. */
async function openRail(user: ReturnType<typeof userEvent.setup>, label: RegExp) {
  await user.click(await screen.findByRole("button", { name: label }));
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
    for (const fn of [
      authorize,
      actOnTenant,
      release,
      elevate,
      elevation,
      endElevation,
      overview,
      tenants,
      diagnostics,
      getDevice,
      tools,
      toolsDiff,
      deadLetters,
    ])
      fn.mockReset();
    // No published estate: these tests are about the act, and the free-entry box is what
    // they drive. The picker has its own file.
    tenants.mockResolvedValue({ entitled: null, served: null });
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
    await waitFor(() => expect(stripText()).toContain("acme"));
    // The countdown is in the strip now, visible from every view rather than only this one.
    await waitFor(() => expect(stripText()).toMatch(/\d+:\d\d/));
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
    // Both the panel and the strip report it — the strip so it survives navigating away,
    // the panel because that is where the operator acquired it. Assert on the panel.
    // The countdown's first value arrives from an effect, so it must be waited for and the
    // panel re-queried each attempt. Asserting synchronously catches the tick before it —
    // which passed locally and failed in CI, the worst way for this to be wrong.
    await waitFor(() => {
      const panel = screen
        .getAllByText(/single use/i)
        .map((el) => el.closest("section"))
        .find(Boolean);
      expect(panel?.textContent).toMatch(/expires in \d+:\d\d/);
    });
    expect(stripText()).toMatch(/single use/i);
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
    await openRail(userEvent.setup(), /^devices$/i);
    await waitFor(() => expect(overview).toHaveBeenCalled());
  });

  it("names whose estate is on screen", async () => {
    // D3, partially: an operator several screens into a device list should not have to
    // remember which customer's hardware they are looking at.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    // The strip answers "whose estate is this" from every view, not just the landing one.
    await waitFor(() => expect(stripText()).toContain("acme"));
    expect(stripText().toLowerCase()).toContain("acting on");
  });

  it("withholds write affordances while D2 is open", async () => {
    // devices:write is inside the gateway ceiling, so this is the console declining rather
    // than the gateway refusing. A ceiling is what the plane may do; a console is what we
    // put a button on.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await openRail(userEvent.setup(), /^devices$/i);
    await waitFor(() => expect(overview).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /delete|register device/i })).not.toBeInTheDocument();
  });

  it("offers monitoring at the same tier as the device list (W2)", async () => {
    // metrics:read is already inside the provider ceiling, so monitoring needs no elevation.
    // If this ever required a step-up, the tier model would have drifted.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    expect(await screen.findByRole("button", { name: /^monitoring$/i })).toBeEnabled();
  });
});

describe("the console shell", () => {
  beforeEach(() => {
    for (const fn of [actOnTenant, elevation, overview, release]) fn.mockReset();
    elevation.mockResolvedValue({ elevation: null });
    overview.mockResolvedValue({ devices: [], counts: {} });
    window.history.replaceState({}, "", "/");
  });

  it("keeps tier-1 destinations visible but disabled without an act", async () => {
    // Hiding them would teach nothing about why they are out of reach, and the "why" is the
    // whole design: signing in reaches no customer stack.
    actOnTenant.mockResolvedValue({ grant: null });
    renderConsole();
    const devices = await screen.findByRole("button", { name: /^devices/i });
    expect(devices).toBeDisabled();
    expect(devices).toHaveTextContent(/needs a live act/i);
  });

  it("says in the strip that nothing is reachable, rather than leaving it blank", async () => {
    // An empty strip reads as "not loaded yet". This reads as the true state.
    actOnTenant.mockResolvedValue({ grant: null });
    renderConsole();
    await waitFor(() => expect(stripText()).toMatch(/no live act/i));
  });

  it("ejects from a tenant view when the act goes away", async () => {
    // §4's point: a screen of a customer's data that outlives the authority to see it is
    // indistinguishable from a live one, so it must not survive the grant.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    const user = userEvent.setup();
    await openRail(user, /^devices$/i);
    await waitFor(() => expect(overview).toHaveBeenCalled());

    // The act ends — from the strip, from expiry, or from another tab. Any of them.
    release.mockResolvedValue({ released: "acme" });
    actOnTenant.mockResolvedValue({ grant: null });
    await user.click(screen.getByRole("button", { name: /end act/i }));

    await waitFor(() => expect(screen.getByRole("button", { name: /^devices/i })).toBeDisabled());
    expect(stripText()).toMatch(/no live act/i);
  });

  it("shows indigo only while an elevation is actually live", async () => {
    // The privilege channel's scarcity is its meaning. If it is on screen at all, the
    // operator is holding elevated authority right now.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await waitFor(() => expect(stripText()).toContain("acme"));
    expect(stripText().toLowerCase()).not.toContain("elevated");
  });

  // --- W5: the Run button is the elevation being visible ----------------------
  //
  // `tools:call` is OUTSIDE the provider ceiling (§5a), so unlike the device list this is not
  // the console declining — it is the only tier that a step-up actually buys. The wiring is
  // one expression (`elevation?.scope === "provider:invoke"`), and hardcoding it true would
  // put a Run button on a customer's live hardware for any operator holding only an act.

  const DEVICE = {
    hostname: "sensor-1",
    base_url: "http://sensor-1.local",
    reachable: true,
    pod_active: true,
  };

  function seedFleet() {
    overview.mockResolvedValue({ devices: [DEVICE], counts: { total: 1, reachable: 1 } });
    diagnostics.mockResolvedValue({
      hostname: "sensor-1",
      mode: "distributed",
      base_url: "http://sensor-1.local",
      spec_url: null,
      reachable: true,
      pod_active: true,
      worker_id: null,
      last_check_age_seconds: 3,
      spec_hash: "abc",
      has_manifest: true,
      tool_count: 1,
      tools_revision: 1,
      spawn_error: null,
      upstream_kind: "mcp",
      breaker: { available: false, note: "not readable here" },
      tls: null,
    });
    getDevice.mockResolvedValue(null);
    toolsDiff.mockResolvedValue(null);
    deadLetters.mockResolvedValue({ hostname: "sensor-1", entries: [], count: 0 });
    tools.mockResolvedValue({
      hostname: "sensor-1",
      count: 1,
      tools: [
        {
          name: "get_readings",
          description: "",
          method: "GET",
          path: "/r",
          schema: { type: "object", properties: {} },
        },
      ],
    });
  }

  async function openTool(user: ReturnType<typeof userEvent.setup>) {
    await openRail(user, /^devices$/i);
    // The fleet table selects through a link, not a button.
    await user.click(await screen.findByRole("link", { name: /sensor-1/ }));
    await user.click(await screen.findByRole("button", { name: /get_readings/ }));
  }

  it("withholds Run while the operator holds only an act", async () => {
    seedFleet();
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await openTool(userEvent.setup());
    expect(screen.queryByRole("button", { name: /^run /i })).not.toBeInTheDocument();
    // ...and says what would change it, rather than leaving the control silently absent.
    expect(screen.getByText(/provider:invoke/)).toBeInTheDocument();
  });

  it("offers Run while a provider:invoke elevation is live", async () => {
    seedFleet();
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    elevation.mockResolvedValue({
      id: "e1",
      tenant: "acme",
      scope: "provider:invoke",
      granted_at: soon(0),
      expires_at: soon(900),
      single_use: false,
    });
    renderConsole();
    await openTool(userEvent.setup());
    expect(screen.getByRole("button", { name: /run get_readings/i })).toBeInTheDocument();
  });

  it("does not accept the credentials elevation as authority to invoke", async () => {
    // The two grants are separate acts (§8). A single-use credentials grant standing in for
    // an invoke one would let a backup step-up buy tool execution on live hardware.
    seedFleet();
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    elevation.mockResolvedValue({
      id: "e2",
      tenant: "acme",
      scope: "provider:credentials",
      granted_at: soon(0),
      expires_at: soon(300),
      single_use: true,
    });
    renderConsole();
    await openTool(userEvent.setup());
    expect(screen.queryByRole("button", { name: /^run /i })).not.toBeInTheDocument();
  });

  // --- W6: backup/restore is tier 2 ------------------------------------------

  it("shows Backup in the rail but needs an act to reach it", async () => {
    // Visible-but-disabled, like the other tier-1 entries: a rail that hid what you cannot
    // yet reach would teach nothing about why, and the why is the whole design.
    renderConsole();
    const backup = await screen.findByRole("button", { name: /^backup/i });
    expect(backup).toBeDisabled();
    expect(backup).toHaveTextContent(/needs a live act/i);
  });

  it("explains the credentials elevation rather than hiding the panel", async () => {
    // An operator with an act but no step-up should learn what would change that. Hiding it
    // until they already held the grant would make the tier invisible.
    actOnTenant.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: soon(0), expires_at: soon(3600) });
    renderConsole();
    await openRail(userEvent.setup(), /^backup$/i);
    expect(await screen.findByText(/provider:credentials/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /prepare export/i })).toBeInTheDocument();
  });

  it("says the credentials elevation is single use once it is held", async () => {
    // The property that makes this grant different from the invoke one: the next operation
    // spends it, so an operator gets one of export-or-restore per step-up. Discovering that
    // by finding the second refused is the outcome this sentence prevents.
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
    await openRail(userEvent.setup(), /^backup$/i);
    // Scoped to the sentence, not the words: the status strip's badge also reads "single
    // use", and matching that would pass without the panel ever explaining anything.
    expect(await screen.findByText(/the next export or restore spends it/i)).toBeInTheDocument();
  });
});
