import { describe, expect, it } from "vitest";
import {
  getSafeAccessSessionReturnTo,
  isAccessSessionEmailAllowed,
  isAccessSessionGrantSessionMatch,
  normalizeAccessEmail,
  resolveAccessIdentityUserId,
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

describe("Access identity mapping", () => {
  it("normalizes email addresses before matching", () => {
    expect(normalizeAccessEmail("  TEAM@Example.COM ")).toBe("team@example.com");
  });

  it("prefers the stable Access subject when it is already mapped", () => {
    expect(
      resolveAccessIdentityUserId({
        accessEmail: "team@example.com",
        subjectUserId: "user-subject",
        subjectEmail: "team@example.com",
        emailUserId: "user-email",
      }),
    ).toEqual({ userId: "user-subject", emailConflict: false });
  });

  it("reuses an existing Better Auth user when the Access subject is new", () => {
    expect(
      resolveAccessIdentityUserId({
        accessEmail: "TEAM@example.com",
        emailUserId: "existing-user",
      }),
    ).toEqual({ userId: "existing-user", emailConflict: false });
  });

  it("rejects a subject whose changed email belongs to another user", () => {
    expect(
      resolveAccessIdentityUserId({
        accessEmail: "new@example.com",
        subjectUserId: "subject-user",
        subjectEmail: "old@example.com",
        emailUserId: "different-user",
      }),
    ).toEqual({ userId: "subject-user", emailConflict: true });
  });
});


describe("Access OAuth grant session binding", () => {
  const now = new Date("2026-11-23T00:00:00.000Z");

  it("accepts only the exact live session for the same user", () => {
    expect(
      isAccessSessionGrantSessionMatch({
        grantSessionId: "session-1",
        grantUserId: "user-1",
        sessionId: "session-1",
        sessionUserId: "user-1",
        expiresAt: new Date("2026-11-24T00:00:00.000Z"),
        now,
      }),
    ).toBe(true);
  });

  it("rejects a missing or different session id", () => {
    expect(
      isAccessSessionGrantSessionMatch({
        grantSessionId: "session-1",
        grantUserId: "user-1",
        sessionId: null,
        sessionUserId: "user-1",
        expiresAt: new Date("2026-11-24T00:00:00.000Z"),
        now,
      }),
    ).toBe(false);
    expect(
      isAccessSessionGrantSessionMatch({
        grantSessionId: "session-1",
        grantUserId: "user-1",
        sessionId: "session-2",
        sessionUserId: "user-1",
        expiresAt: new Date("2026-11-24T00:00:00.000Z"),
        now,
      }),
    ).toBe(false);
  });

  it("rejects a different user and an expired session", () => {
    expect(
      isAccessSessionGrantSessionMatch({
        grantSessionId: "session-1",
        grantUserId: "user-1",
        sessionId: "session-1",
        sessionUserId: "user-2",
        expiresAt: new Date("2026-11-24T00:00:00.000Z"),
        now,
      }),
    ).toBe(false);
    expect(
      isAccessSessionGrantSessionMatch({
        grantSessionId: "session-1",
        grantUserId: "user-1",
        sessionId: "session-1",
        sessionUserId: "user-1",
        expiresAt: new Date("2026-11-22T00:00:00.000Z"),
        now,
      }),
    ).toBe(false);
  });
});
