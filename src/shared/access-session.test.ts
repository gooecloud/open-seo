import { describe, expect, it } from "vitest";
import {
  getSafeAccessSessionReturnTo,
  isAccessSessionEmailAllowed,
} from "./access-session";

describe("isAccessSessionEmailAllowed", () => {
  it("matches normalized email addresses", () => {
    expect(
      isAccessSessionEmailAllowed(
        "TEAM@example.com",
        "admin@example.com, team@example.com",
      ),
    ).toBe(true);
  });

  it("denies missing and unlisted email addresses", () => {
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
      getSafeAccessSessionReturnTo(
        "/api/auth/oauth2/authorize?client_id=abc",
        origin,
      ),
    ).toBe("/api/auth/oauth2/authorize?client_id=abc");
  });

  it.each([
    "https://evil.example/path",
    "//evil.example/path",
    "/api/auth/access-session/login?returnTo=%2F",
    undefined,
    "",
  ])("falls back to the root for unsafe return targets: %s", (value) => {
    expect(getSafeAccessSessionReturnTo(value, origin)).toBe("/");
  });
});
