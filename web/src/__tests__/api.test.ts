// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The `req` helper's error extraction. Every other test in this suite mocks `../api`
// wholesale, so this is the only place `req`'s own body-parsing runs at all — and it is
// exactly where ADR-0018 §6's `ERR_PLAN_STALE` broke: its `detail` is a dict, not a string,
// and the naive `detail.detail` read handed that object straight to `ApiError`'s message,
// which renders as "[object Object]" rather than the sentence telling an operator what to do.
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "../api";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("req error extraction", () => {
  it("reads a plain string detail as the message, as most gateway errors are", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(409, { detail: "already registered" })));
    await expect(api.overview()).rejects.toMatchObject({ status: 409, message: "already registered" });
  });

  it("reads a structured detail's `message` field, as ERR_PLAN_STALE's does", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(409, {
          detail: { error_code: "ERR_PLAN_STALE", message: "plan_token does not match this request", fields: [] },
        }),
      ),
    );
    const err = await api.overview().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toBe("plan_token does not match this request");
  });

  it("falls back to the status text when there is no usable detail at all", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not json", { status: 500, statusText: "Internal Server Error" })),
    );
    await expect(api.overview()).rejects.toMatchObject({ status: 500, message: "Internal Server Error" });
  });
});
