export const ACCESS_SESSION_BRIDGE_PATH = "/auth/access-bridge";
export const ACCESS_SESSION_STATUS_PATH = "/api/auth/access-session";
export const ACCESS_SESSION_LOGOUT_PATH = "/api/auth/access-session/logout";
export const ACCESS_SESSION_REVOKE_PATH = "/api/auth/access-session/revoke";

export function parseAccessSessionEmailAllowlist(value: string | undefined) {
  return new Set(
    (value ?? "")
      .split(",")
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function isAccessSessionEmailAllowed(
  email: string,
  allowlist: string | undefined,
) {
  return parseAccessSessionEmailAllowlist(allowlist).has(
    email.trim().toLowerCase(),
  );
}

export function getSafeAccessSessionReturnTo(
  value: string | null,
  origin: string,
) {
  if (!value || !value.startsWith("/") || value.startsWith("//")) {
    return "/";
  }

  try {
    const target = new URL(value, origin);
    if (
      target.origin !== origin ||
      target.pathname === ACCESS_SESSION_BRIDGE_PATH
    ) {
      return "/";
    }

    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return "/";
  }
}
