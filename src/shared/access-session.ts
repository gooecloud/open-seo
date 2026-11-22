export const ACCESS_SESSION_LOGIN_PATH = "/api/auth/access-session/login";
export const ACCESS_SESSION_REVOKE_USER_PATH =
  "/api/auth/access-session/revoke-user";

export function normalizeAccessEmail(email: string) {
  return email.trim().toLowerCase();
}

export function resolveAccessIdentityUserId(input: {
  accessEmail: string;
  subjectUserId?: string | null;
  subjectEmail?: string | null;
  emailUserId?: string | null;
}) {
  const subjectUserId = input.subjectUserId ?? null;
  const emailUserId = input.emailUserId ?? null;
  const emailConflict =
    Boolean(subjectUserId) &&
    Boolean(emailUserId) &&
    subjectUserId !== emailUserId &&
    normalizeAccessEmail(input.subjectEmail ?? "") !==
      normalizeAccessEmail(input.accessEmail);

  return {
    userId: subjectUserId ?? emailUserId,
    emailConflict,
  };
}

export function isAccessSessionEmailAllowed(
  email: string,
  allowlist: string | undefined,
) {
  return new Set(
    (allowlist ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  ).has(email.trim().toLowerCase());
}

export function getSafeAccessSessionReturnTo(
  value: string | undefined,
  origin: string,
) {
  if (!value || !value.startsWith("/") || value.startsWith("//")) {
    return "/";
  }

  try {
    const target = new URL(value, origin);
    if (
      target.origin !== origin ||
      target.pathname === ACCESS_SESSION_LOGIN_PATH
    ) {
      return "/";
    }

    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return "/";
  }
}
