export const ACCESS_SESSION_LOGIN_PATH = "/api/auth/access-session/login";
export const ACCESS_SESSION_REVOKE_USER_PATH =
  "/api/auth/access-session/revoke-user";

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
