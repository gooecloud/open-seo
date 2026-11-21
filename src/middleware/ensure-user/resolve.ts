import { env } from "cloudflare:workers";
import { getAuthMode, isAccessSessionAuthMode, isHostedAuthMode } from "@/lib/auth-mode";
import { resolveAccessSessionContext } from "@/server/auth/access-session";
import { resolveCloudflareAccessContext } from "./cloudflareAccess";
import { resolveLocalNoAuthContext } from "./delegated";
import { resolveHostedContext } from "./hosted";
import type { EnsuredUserContext } from "./types";

// Resolves the authenticated user for a request's headers across every auth
// mode. Shared by ensureUserMiddleware (server functions) and raw API routes,
// which can't use function middleware.
export async function resolveUserContextFromHeaders(
  headers: Headers,
): Promise<EnsuredUserContext> {
  const authMode = getAuthMode(env.AUTH_MODE);
  if (authMode === "local_noauth") {
    return resolveLocalNoAuthContext();
  }
  if (isAccessSessionAuthMode(authMode)) {
    return resolveAccessSessionContext(headers);
  }
  if (isHostedAuthMode(authMode)) {
    return resolveHostedContext(headers);
  }
  return resolveCloudflareAccessContext(headers);
}
