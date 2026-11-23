import { useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { useSession } from "@/lib/auth-client";
import {
  isAccessSessionClientAuthMode,
  isEmailVerificationBypassed,
  isHostedClientAuthMode,
} from "@/lib/auth-mode";
import {
  getCurrentAuthRedirectFromHref,
  getSignInSearch,
  getVerifyEmailSearch,
} from "@/lib/auth-redirect";

export function useHostedAuthRouteGuard() {
  const navigate = useNavigate();
  const { data: session, isPending } = useSession();
  const isHostedMode = isHostedClientAuthMode();
  const isAccessSessionMode = isAccessSessionClientAuthMode();
  const emailVerified =
    session?.user?.emailVerified === true || isEmailVerificationBypassed();

  useEffect(() => {
    if (isPending || (!isHostedMode && !isAccessSessionMode)) {
      return;
    }

    const redirectTo = getCurrentAuthRedirectFromHref(window.location.href);

    if (!session?.user?.id) {
      // Do not silently re-enter Cloudflare Access after sign-out. The sign-in
      // page exposes an explicit "Continue with company account" action, so
      // users can end the application session while their Access SSO remains
      // active in the browser.
      void navigate({
        to: "/sign-in",
        search: getSignInSearch(redirectTo),
        replace: true,
      });
      return;
    }

    if (isHostedMode && !emailVerified) {
      void navigate({
        to: "/verify-email",
        search: getVerifyEmailSearch(session.user.email, redirectTo),
        replace: true,
      });
    }
  }, [
    isPending,
    isHostedMode,
    isAccessSessionMode,
    emailVerified,
    session?.user?.email,
    session?.user?.id,
    navigate,
  ]);

  const hasVerifiedHostedSession =
    !isPending && Boolean(session?.user?.id) && emailVerified;

  return {
    isHostedMode: isHostedMode || isAccessSessionMode,
    canRenderAuthenticatedContent:
      !(isHostedMode || isAccessSessionMode) || hasVerifiedHostedSession,
  };
}
