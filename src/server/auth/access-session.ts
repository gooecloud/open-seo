import { and, eq, gt, like, sql } from "drizzle-orm";
import { z } from "zod";
import { env } from "cloudflare:workers";
import { db } from "@/db";
import { session as authSession, user as authUser } from "@/db/schema";
import { resolveCloudflareAccessContext } from "@/middleware/ensure-user/cloudflareAccess";
import { resolveSharedWorkspaceContext } from "@/middleware/ensure-user/delegated";
import type { EnsuredUserContext } from "@/middleware/ensure-user/types";
import { AppError, asAppError } from "@/server/lib/errors";
import {
  ACCESS_SESSION_BRIDGE_PATH,
  ACCESS_SESSION_LOGOUT_PATH,
  ACCESS_SESSION_REVOKE_PATH,
  ACCESS_SESSION_STATUS_PATH,
  getSafeAccessSessionReturnTo,
  isAccessSessionEmailAllowed,
} from "@/shared/access-session";

const ACCESS_SESSION_COOKIE_NAME = "__Host-open-seo-session";
const ACCESS_SESSION_TOKEN_PREFIX = "oas1:";
const ACCESS_SESSION_TTL_SECONDS = 90 * 24 * 60 * 60;
const ACCESS_SESSION_RENEWAL_WINDOW_SECONDS = 15 * 24 * 60 * 60;
const ACCESS_SESSION_TTL_MS = ACCESS_SESSION_TTL_SECONDS * 1000;
const ACCESS_SESSION_RENEWAL_WINDOW_MS =
  ACCESS_SESSION_RENEWAL_WINDOW_SECONDS * 1000;
const ACCESS_SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

type AccessSessionRecord = {
  session: typeof authSession.$inferSelect;
  user: Pick<typeof authUser.$inferSelect, "id" | "email">;
};

function isAllowedEmail(email: string) {
  return isAccessSessionEmailAllowed(email, env.ACCESS_ALLOWED_EMAILS);
}

function isAdminEmail(email: string) {
  return isAccessSessionEmailAllowed(email, env.ACCESS_SESSION_ADMIN_EMAILS);
}

function readSessionCookie(headers: Headers) {
  const cookieHeader = headers.get("cookie");
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== ACCESS_SESSION_COOKIE_NAME) {
      continue;
    }

    const value = part.slice(separator + 1).trim();
    return ACCESS_SESSION_TOKEN_PATTERN.test(value) ? value : null;
  }

  return null;
}

function encodeBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createSessionToken() {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function hashSessionToken(token: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return encodeBase64Url(new Uint8Array(digest));
}

function sessionCookie(token: string) {
  return `${ACCESS_SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${ACCESS_SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

function clearedSessionCookie() {
  return `${ACCESS_SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function withSetCookie(response: Response, cookie: string) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function findActiveSessionByCookie(
  headers: Headers,
): Promise<AccessSessionRecord | null> {
  const token = readSessionCookie(headers);
  if (!token) return null;

  const tokenHash = await hashSessionToken(token);
  const storedToken = `${ACCESS_SESSION_TOKEN_PREFIX}${tokenHash}`;
  const now = new Date();
  const session = await db.query.session.findFirst({
    where: and(eq(authSession.token, storedToken), gt(authSession.expiresAt, now)),
  });
  if (!session) return null;

  const user = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(authUser.id, session.userId),
  });
  if (!user?.email || !isAllowedEmail(user.email)) return null;

  return { session, user };
}

async function findActiveSessionForUser(
  userId: string,
): Promise<AccessSessionRecord | null> {
  const now = new Date();
  const session = await db.query.session.findFirst({
    where: and(
      eq(authSession.userId, userId),
      like(authSession.token, `${ACCESS_SESSION_TOKEN_PREFIX}%`),
      gt(authSession.expiresAt, now),
    ),
  });
  if (!session) return null;

  const user = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(authUser.id, userId),
  });
  if (!user?.email || !isAllowedEmail(user.email)) return null;

  return { session, user };
}

async function extendAccessSessionsIfNeeded(userId: string) {
  const now = new Date();
  const session = await db.query.session.findFirst({
    where: and(
      eq(authSession.userId, userId),
      like(authSession.token, `${ACCESS_SESSION_TOKEN_PREFIX}%`),
      gt(authSession.expiresAt, now),
    ),
  });
  if (!session) return;

  const renewAt = new Date(
    now.getTime() + ACCESS_SESSION_RENEWAL_WINDOW_MS,
  );
  if (session.expiresAt.getTime() > renewAt.getTime()) return;

  await db
    .update(authSession)
    .set({
      expiresAt: new Date(now.getTime() + ACCESS_SESSION_TTL_MS),
      updatedAt: now,
    })
    .where(
      and(
        eq(authSession.userId, userId),
        like(authSession.token, `${ACCESS_SESSION_TOKEN_PREFIX}%`),
        gt(authSession.expiresAt, now),
      ),
    );
}

async function createAccessSession(
  request: Request,
  identity: EnsuredUserContext,
) {
  const token = createSessionToken();
  const tokenHash = await hashSessionToken(token);
  const now = new Date();

  await db.insert(authSession).values({
    id: crypto.randomUUID(),
    token: `${ACCESS_SESSION_TOKEN_PREFIX}${tokenHash}`,
    userId: identity.userId,
    activeOrganizationId: identity.organizationId,
    expiresAt: new Date(now.getTime() + ACCESS_SESSION_TTL_MS),
    createdAt: now,
    updatedAt: now,
    ipAddress: request.headers.get("cf-connecting-ip"),
    userAgent: request.headers.get("user-agent"),
  });

  return token;
}

function isSameOriginRequest(request: Request) {
  return request.headers.get("origin") === new URL(request.url).origin;
}

export function redirectToAccessSessionBridge(request: Request) {
  const current = new URL(request.url);
  const bridge = new URL(ACCESS_SESSION_BRIDGE_PATH, current.origin);
  bridge.searchParams.set(
    "returnTo",
    `${current.pathname}${current.search}`,
  );
  return Response.redirect(bridge.toString(), 302);
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

  const record = await findActiveSessionByCookie(headers);
  if (!record) throw new AppError("UNAUTHENTICATED");

  return resolveSharedWorkspaceContext(record.user.id, record.user.email);
}

export async function resolveAccessSessionMcpContext(
  userId: string,
  userEmail: string,
): Promise<EnsuredUserContext | null> {
  if (!env.ACCESS_ALLOWED_EMAILS?.trim()) return null;

  const record = await findActiveSessionForUser(userId);
  if (
    !record ||
    record.user.email.trim().toLowerCase() !== userEmail.trim().toLowerCase()
  ) {
    return null;
  }

  await extendAccessSessionsIfNeeded(userId);
  return resolveSharedWorkspaceContext(userId, record.user.email);
}

export async function handleAccessSessionBridge(request: Request) {
  if (request.method !== "GET") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "GET" },
    });
  }

  if (!env.ACCESS_ALLOWED_EMAILS?.trim()) {
    return new Response("ACCESS_ALLOWED_EMAILS is not configured", {
      status: 503,
    });
  }

  let identity: EnsuredUserContext;
  try {
    identity = await resolveCloudflareAccessContext(request.headers);
  } catch (error) {
    const appError = asAppError(error);
    if (appError?.code === "UNAUTHENTICATED") {
      return new Response("Cloudflare Access authentication is required", {
        status: 401,
      });
    }
    if (appError?.code === "AUTH_CONFIG_MISSING") {
      return new Response(
        "The Cloudflare Access session bootstrap route is not configured",
        { status: 503 },
      );
    }
    throw error;
  }

  if (!isAllowedEmail(identity.userEmail)) {
    return new Response("This email is not on the employee allowlist", {
      status: 403,
    });
  }

  const token = await createAccessSession(request, identity);
  const url = new URL(request.url);
  const returnTo = getSafeAccessSessionReturnTo(
    url.searchParams.get("returnTo"),
    url.origin,
  );
  const headers = new Headers({
    Location: new URL(returnTo, url.origin).toString(),
  });
  headers.append("Set-Cookie", sessionCookie(token));

  return new Response(null, { status: 302, headers });
}

export async function handleAccessSessionStatus(request: Request) {
  if (request.method !== "GET") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "GET" },
    });
  }

  const record = await findActiveSessionByCookie(request.headers);
  if (!record) {
    return Response.json({ error: "unauthenticated" }, { status: 401 });
  }

  return Response.json({
    userId: record.user.id,
    email: record.user.email,
    expiresAt: record.session.expiresAt.toISOString(),
  });
}

export async function handleAccessSessionLogout(request: Request) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST" },
    });
  }
  if (!isSameOriginRequest(request)) {
    return new Response("Invalid request origin", { status: 403 });
  }

  const token = readSessionCookie(request.headers);
  if (token) {
    const tokenHash = await hashSessionToken(token);
    await db
      .delete(authSession)
      .where(
        eq(
          authSession.token,
          `${ACCESS_SESSION_TOKEN_PREFIX}${tokenHash}`,
        ),
      );
  }

  return withSetCookie(new Response(null, { status: 204 }), clearedSessionCookie());
}

export async function handleAccessSessionRevoke(request: Request) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST" },
    });
  }
  if (!isSameOriginRequest(request)) {
    return new Response("Invalid request origin", { status: 403 });
  }

  const actor = await findActiveSessionByCookie(request.headers);
  if (!actor) return new Response("Unauthorized", { status: 401 });
  if (!isAdminEmail(actor.user.email)) {
    return new Response("Administrator access required", { status: 403 });
  }

  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    return Response.json({ error: "Invalid request body" }, { status: 400 });
  }

  const body = z.object({ email: z.string().trim().email() }).safeParse(rawBody);
  if (!body.success) {
    return Response.json({ error: "A valid employee email is required" }, { status: 400 });
  }

  const target = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(sql`lower(${authUser.email})`, body.data.email.toLowerCase()),
  });
  if (!target) return new Response("User not found", { status: 404 });

  await db
    .delete(authSession)
    .where(
      and(
        eq(authSession.userId, target.id),
        like(authSession.token, `${ACCESS_SESSION_TOKEN_PREFIX}%`),
      ),
    );

  return Response.json({ revoked: true, email: target.email });
}

export async function refreshAccessSessionCookie(
  request: Request,
  response: Response,
) {
  if (!readSessionCookie(request.headers)) return response;

  try {
    const record = await findActiveSessionByCookie(request.headers);
    if (!record) return withSetCookie(response, clearedSessionCookie());

    const renewAt = Date.now() + ACCESS_SESSION_RENEWAL_WINDOW_MS;
    if (record.session.expiresAt.getTime() > renewAt) return response;

    const now = new Date();
    await db
      .update(authSession)
      .set({
        expiresAt: new Date(now.getTime() + ACCESS_SESSION_TTL_MS),
        updatedAt: now,
      })
      .where(eq(authSession.id, record.session.id));

    const token = readSessionCookie(request.headers);
    return token ? withSetCookie(response, sessionCookie(token)) : response;
  } catch (error) {
    console.error("[access-session] rolling renewal failed", error);
    return response;
  }
}

export const ACCESS_SESSION_PATHS = {
  bridge: ACCESS_SESSION_BRIDGE_PATH,
  status: ACCESS_SESSION_STATUS_PATH,
  logout: ACCESS_SESSION_LOGOUT_PATH,
  revoke: ACCESS_SESSION_REVOKE_PATH,
} as const;
