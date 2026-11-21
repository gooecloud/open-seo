import { describe, expect, it } from "vitest";
import {
  getSafeAccessSessionReturnTo,
  isAccessSessionEmailAllowed,
  parseAccessSessionEmailAllowlist,
} from "./access-session";

describe("access session allowlist", () => {
  it("normalizes email addresses and ignores empty entries", () => {
    expect(
      parseAccessSessionEmailAllowlist(" Admin@Example.com, , team@example.com "),
    ).toEqual(new Set(["admin@example.com", "team@example.com"]));
  });

  it("matches employee email addresses case-insensitively", () => {
    expect(
      isAccessSessionEmailAllowed(
        "TEAM@example.com",
        "admin@example.com,team@example.com",
      ),
    ).toBe(true);
    expect(
      isAccessSessionEmailAllowed("other@example.com", "team@example.com"),
    ).toBe(false);
    expect(isAccessSessionEmailAllowed("team@example.com", undefined)).toBe(
      false,
    );
  });
});

describe("getSafeAccessSessionReturnTo", () => {
  const origin = "https://preview.example.workers.dev";

  it("preserves a same-origin path and query", () => {
    expect(
      getSafeAccessSessionReturnTo("/api/auth/oauth2/authorize?client_id=abc", origin),
    ).toBe("/api/auth/oauth2/authorize?client_id=abc");
  });

  it.each([
    "https://evil.example/path",
    "//evil.example/path",
    "/auth/access-bridge?returnTo=%2F",
    null,
    "",
  ])("falls back to the root for unsafe return targets: %s", (value) => {
    expect(getSafeAccessSessionReturnTo(value, origin)).toBe("/");
  });
});
