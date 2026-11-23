import { and, eq, gt } from "drizzle-orm";
import { env } from "cloudflare:workers";
import { db } from "@/db";
import { session as authSession, user as authUser } from "@/db/schema";
import {
  isAccessSessionEmailAllowed,
  isAccessSessionGrantSessionMatch,
} from "@/shared/access-session";
import { getAuth } from "@/lib/auth";
import { resolveSharedWorkspaceContext } from "@/middleware/ensure-user/delegated";
import { AppError } from "@/server/lib/errors";
import type { EnsuredUserContext } from "@/middleware/ensure-user/types";

export function isAccessSessionAllowed(email: string) {
  return isAccessSessionEmailAllowed(email, env.ACCESS_ALLOWED_EMAILS);
}

export async function resolveAccessSessionOAuthContext(
  userId: string,
  userEmail: string,
  sessionId?: string,
): Promise<EnsuredUserContext | null> {
  if (
    !sessionId ||
    !env.ACCESS_ALLOWED_EMAILS?.trim() ||
    !isAccessSessionAllowed(userEmail)
  ) {
    return null;
  }

  const user = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(authUser.id, userId),
  });
  if (
    !user ||
    user.email.trim().toLowerCase() !== userEmail.trim().toLowerCase()
  ) {
    return null;
  }

  const now = new Date();
  const activeSession = await db.query.session.findFirst({
    columns: { id: true, userId: true, expiresAt: true },
    where: and(
      eq(authSession.id, sessionId),
      eq(authSession.userId, userId),
      gt(authSession.expiresAt, now),
    ),
  });

  if (
    !isAccessSessionGrantSessionMatch({
      grantSessionId: sessionId,
      grantUserId: userId,
      sessionId: activeSession?.id,
      sessionUserId: activeSession?.userId,
      expiresAt: activeSession?.expiresAt,
      now,
    })
  ) {
    return null;
  }

  return resolveSharedWorkspaceContext(user.id, user.email);
}

export async function resolveAccessSessionGrantIdentity(
  headers: Headers,
): Promise<{ sessionId: string; userId: string; userEmail: string } | null> {
  if (!env.ACCESS_ALLOWED_EMAILS?.trim()) return null;

  const current = await getAuth().api.getSession({
    headers,
    query: { disableCookieCache: true },
  });

  if (
    !current?.session?.id ||
    !current.user?.id ||
    !current.user.email ||
    !isAccessSessionAllowed(current.user.email)
  ) {
    return null;
  }

  const user = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(authUser.id, current.user.id),
  });
  if (
    !user ||
    user.email.trim().toLowerCase() !== current.user.email.trim().toLowerCase()
  ) {
    return null;
  }

  return {
    sessionId: current.session.id,
    userId: user.id,
    userEmail: user.email,
  };
}

export async function resolveAccessSessionContext(
  headers: Headers,
): Promise<EnsuredUserContext> {
  if (!env.ACCESS_ALLOWED_EMAILS?.trim()) {
    throw new AppError(
      "AUTH_CONFIG_MISSING",
      "ACCESS_ALLOWED_EMAILS is required for access_session mode",
    );
  }

  const session = await getAuth().api.getSession({
    headers,
    query: { disableCookieCache: true },
  });

  if (
    !session?.user?.id ||
    !session.user.email ||
    !isAccessSessionAllowed(session.user.email)
  ) {
    throw new AppError("UNAUTHENTICATED");
  }

  return resolveSharedWorkspaceContext(session.user.id, session.user.email);
}
