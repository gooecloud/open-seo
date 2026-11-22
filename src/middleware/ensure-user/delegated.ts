import { db } from "@/db";
import { user } from "@/db/schema";
import {
  ensureDelegatedOrganizationForUser,
  ensureSharedWorkspaceOrganization,
} from "@/server/auth/delegated-organization";
import { AppError } from "@/server/lib/errors";
import { eq, sql } from "drizzle-orm";
import type { EnsuredUserContext } from "./types";

const LOCAL_ADMIN_USER_ID = "local-admin";
const LOCAL_ADMIN_EMAIL = "admin@localhost";

// Externally-authenticated users (Cloudflare Access, local_noauth) are stored
// in better-auth's `user` table just like hosted users — only the way they
// authenticate them differs (per-request, no better-auth session). Keeping a
// single user table means OAuth grants and every app table reference one id.
function deriveUserName(email: string) {
  return email.split("@")[0] || "OpenSEO";
}

async function findUserByEmail(email: string) {
  return db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(sql`lower(${user.email})`, email.trim().toLowerCase()),
  });
}

async function ensureUserRecord(
  accessSubject: string,
  accessEmail: string,
): Promise<{ userId: string; email: string }> {
  const email = accessEmail.trim();
  const normalizedEmail = email.toLowerCase();

  // Cloudflare Access `sub` is its stable identity subject, not necessarily
  // the Better Auth user id. Prefer the subject mapping when it already
  // exists, and fail closed if that subject is suddenly presented with an
  // email already owned by another user.
  const existingBySubject = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(user.id, accessSubject),
  });

  if (existingBySubject) {
    if (existingBySubject.email.trim().toLowerCase() !== normalizedEmail) {
      const emailOwner = await findUserByEmail(email);
      if (emailOwner && emailOwner.id !== existingBySubject.id) {
        throw new AppError(
          "UNAUTHENTICATED",
          "Cloudflare Access identity email is already linked to another user",
        );
      }

      await db
        .update(user)
        .set({ email, name: deriveUserName(email) })
        .where(eq(user.id, existingBySubject.id));
    }

    return { userId: existingBySubject.id, email };
  }

  // Older self-hosted/hosted records may predate the Access subject id. Reuse
  // the existing Better Auth user by case-insensitive email rather than
  // creating a second user that collides with the unique email constraint.
  const existingByEmail = await findUserByEmail(email);
  if (existingByEmail) {
    return {
      userId: existingByEmail.id,
      email: existingByEmail.email,
    };
  }

  try {
    await db
      .insert(user)
      .values({
        id: accessSubject,
        name: deriveUserName(email),
        email,
        emailVerified: true,
      })
      .onConflictDoNothing({ target: user.id });
  } catch (error) {
    // Two different Access subjects can arrive concurrently with the same
    // verified email. Resolve the winner to its canonical user id; otherwise
    // preserve the original database error.
    const racedEmailOwner = await findUserByEmail(email);
    if (racedEmailOwner) {
      return {
        userId: racedEmailOwner.id,
        email: racedEmailOwner.email,
      };
    }
    throw error;
  }

  const insertedOrRaced = await db.query.user.findFirst({
    columns: { id: true, email: true },
    where: eq(user.id, accessSubject),
  });
  if (insertedOrRaced) {
    if (insertedOrRaced.email.trim().toLowerCase() !== normalizedEmail) {
      throw new AppError(
        "UNAUTHENTICATED",
        "Cloudflare Access subject is already linked to a different email",
      );
    }
    return { userId: insertedOrRaced.id, email: insertedOrRaced.email };
  }

  const racedEmailOwner = await findUserByEmail(email);
  if (racedEmailOwner) {
    return {
      userId: racedEmailOwner.id,
      email: racedEmailOwner.email,
    };
  }

  throw new Error("Unable to persist Cloudflare Access user identity");
}

async function resolveDelegatedContext(
  userId: string,
  userEmail: string,
): Promise<EnsuredUserContext> {
  const identity = await ensureUserRecord(userId, userEmail);
  const organizationId = await ensureDelegatedOrganizationForUser(
    identity.userId,
    identity.email,
  );

  return {
    userId: identity.userId,
    userEmail: identity.email,
    // Delegated auth (Cloudflare Access / local) has no unverified state.
    emailVerified: true,
    organizationId,
    // Delegated orgs are one-implicit-user with no member rows; that user has
    // full control of their own workspace.
    role: "owner",
  };
}

// Cloudflare Access mode: everyone the Access policy lets in works in one
// shared workspace, keeping their own user identity. Per-user workspaces were
// the pre-shared-workspace behavior; workspace-merge.ts folds those in.
export async function resolveSharedWorkspaceContext(
  userId: string,
  userEmail: string,
): Promise<EnsuredUserContext> {
  const identity = await ensureUserRecord(userId, userEmail);
  const organizationId = await ensureSharedWorkspaceOrganization();

  return {
    userId: identity.userId,
    userEmail: identity.email,
    emailVerified: true,
    organizationId,
    // The Access policy is the authorization boundary; everyone it admits has
    // full control of the shared workspace.
    role: "owner",
  };
}

export async function resolveLocalNoAuthContext(): Promise<EnsuredUserContext> {
  return resolveDelegatedContext(LOCAL_ADMIN_USER_ID, LOCAL_ADMIN_EMAIL);
}
