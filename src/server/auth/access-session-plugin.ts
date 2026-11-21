import { and, eq, sql } from "drizzle-orm";
import { env } from "cloudflare:workers";
import { APIError, createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth";
import { setSessionCookie } from "better-auth/cookies";
import { z } from "zod";
import { db } from "@/db";
import { user as authUser } from "@/db/schema";
import { resolveCloudflareAccessContext } from "@/middleware/ensure-user/cloudflareAccess";
import { asAppError } from "@/server/lib/errors";
import {
  getSafeAccessSessionReturnTo,
  isAccessSessionEmailAllowed,
} from "@/shared/access-session";

function isAllowedEmail(email: string) {
  return isAccessSessionEmailAllowed(email, env.ACCESS_ALLOWED_EMAILS);
}

function isAdminEmail(email: string) {
  return isAccessSessionEmailAllowed(email, env.ACCESS_SESSION_ADMIN_EMAILS);
}

export function accessSessionPlugin() {
  return {
    id: "open-seo-access-session",
    endpoints: {
      accessSessionLogin: createAuthEndpoint(
        "/access-session/login",
        {
          method: "GET",
          query: z.object({ returnTo: z.string().optional() }),
        },
        async (ctx) => {
          if (!env.ACCESS_ALLOWED_EMAILS?.trim()) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "ACCESS_ALLOWED_EMAILS is not configured",
            });
          }

          let identity;
          try {
            identity = await resolveCloudflareAccessContext(ctx.request.headers);
          } catch (error) {
            const appError = asAppError(error);
            if (appError?.code === "AUTH_CONFIG_MISSING") {
              throw new APIError("INTERNAL_SERVER_ERROR", {
                message: "Cloudflare Access bootstrap is not configured",
              });
            }
            throw new APIError("UNAUTHORIZED", {
              message: "Cloudflare Access authentication is required",
            });
          }

          if (!isAllowedEmail(identity.userEmail)) {
            throw new APIError("FORBIDDEN", {
              message: "This email is not on the SEO employee allowlist",
            });
          }

          const user = await db.query.user.findFirst({
            where: eq(authUser.id, identity.userId),
          });
          if (!user) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Unable to resolve the authenticated employee",
            });
          }

          const session = await ctx.context.internalAdapter.createSession(
            user.id,
            false,
          );
          if (!session) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Unable to create the SEO application session",
            });
          }

          await setSessionCookie(ctx, { session, user });

          const origin = new URL(ctx.request.url).origin;
          const returnTo = getSafeAccessSessionReturnTo(
            ctx.query.returnTo,
            origin,
          );
          throw ctx.redirect(new URL(returnTo, origin).toString());
        },
      ),
      revokeUserSessions: createAuthEndpoint(
        "/access-session/revoke-user",
        {
          method: "POST",
          body: z.object({ email: z.string().trim().email() }),
        },
        async (ctx) => {
          if (ctx.request.headers.get("origin") !== new URL(ctx.request.url).origin) {
            throw new APIError("FORBIDDEN", {
              message: "Invalid request origin",
            });
          }

          const actor = await getSessionFromCtx(ctx, {
            disableCookieCache: true,
          });
          if (!actor?.user?.email) {
            throw new APIError("UNAUTHORIZED", {
              message: "A valid SEO application session is required",
            });
          }
          if (!isAdminEmail(actor.user.email)) {
            throw new APIError("FORBIDDEN", {
              message: "Administrator access is required",
            });
          }

          const target = await db.query.user.findFirst({
            columns: { id: true, email: true },
            where: eq(
              sql`lower(${authUser.email})`,
              ctx.body.email.toLowerCase(),
            ),
          });
          if (!target) {
            throw new APIError("NOT_FOUND", {
              message: "Employee not found",
            });
          }
          if (target.id === actor.user.id) {
            throw new APIError("BAD_REQUEST", {
              message: "Use Sign out to end your own session",
            });
          }

          await ctx.context.internalAdapter.deleteUserSessions(target.id);
          return ctx.json({ revoked: true, email: target.email });
        },
      ),
    },
  } satisfies BetterAuthPlugin;
}
