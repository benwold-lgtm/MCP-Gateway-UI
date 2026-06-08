// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Vitest setup: jest-dom matchers + unmount React trees between tests.
// Explicit cleanup (rather than relying on vitest `globals`) so each test starts
// from a clean DOM — otherwise renders accumulate and queries find duplicates.
import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
});
