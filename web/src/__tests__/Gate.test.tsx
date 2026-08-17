// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Gate } from "../components/Gate";
import { priv } from "../tokens";

describe("Gate", () => {
  it("says which state it is in, for anyone not looking at it", () => {
    // It is the only motion in the product, which makes it exactly the kind of thing that
    // communicates nothing to a screen reader unless it is made to.
    const { rerender } = render(<Gate open={false} />);
    expect(screen.getByRole("img", { name: /closed/i })).toBeInTheDocument();
    rerender(<Gate open={true} />);
    expect(screen.getByRole("img", { name: /open/i })).toBeInTheDocument();
  });

  it("does not animate on mount, only on a change", () => {
    // A console reloaded while a grant is live should show an open gate, not replay the
    // opening — nothing just happened, and a motion that fires on every mount stops meaning
    // "this changed".
    const { container } = render(<Gate open={true} />);
    const moved = container.querySelectorAll("g");
    expect(moved.length).toBeGreaterThan(0);
    moved.forEach((g) => expect(g.style.transition).toBe("none"));
  });

  it("carries the privilege colour when open and drops it when closed", () => {
    // The gate is the one place the elevation state is rendered as a picture, so it has to
    // obey the same rule as everything else: indigo means elevated authority, right now.
    const { container: openC } = render(<Gate open={true} />);
    expect(openC.innerHTML.toLowerCase()).toContain(priv.base.toLowerCase());

    const { container: shutC } = render(<Gate open={false} />);
    expect(shutC.innerHTML.toLowerCase()).not.toContain(priv.base.toLowerCase());
  });

  it("differs in shape between states, not only in having moved", () => {
    // The reduced-motion path removes the transition. Both end states still have to be
    // readable, so the leaves must actually sit somewhere different rather than relying on
    // the animation to convey the change.
    const { container: openC } = render(<Gate open={true} />);
    const { container: shutC } = render(<Gate open={false} />);
    const transform = (c: HTMLElement) => Array.from(c.querySelectorAll("g")).map((g) => g.style.transform);
    expect(transform(openC)).not.toEqual(transform(shutC));
    expect(transform(shutC).every((t) => t.includes("0px"))).toBe(true);
  });
});
