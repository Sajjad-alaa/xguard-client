import { ClientTrafficPolicy } from '../rust-api/types';

type Policy = (typeof ClientTrafficPolicy)[keyof typeof ClientTrafficPolicy];

/**
 * Whether a location routes all traffic, given the policy the instance's administrator set.
 * The Rust side applies the same rule when it brings the tunnel up; this only keeps the UI in
 * line with it. Bare tunnels have no instance and therefore no policy.
 */
export const effectiveRouteAllTraffic = (
  policy: Policy | undefined,
  routeAllTraffic: boolean,
): boolean => {
  switch (policy) {
    case ClientTrafficPolicy.ForceAllTraffic:
      return true;
    case ClientTrafficPolicy.DisableAllTraffic:
      return false;
    default:
      return routeAllTraffic;
  }
};

/** Whether the user may choose the routing themselves. */
export const canChooseRouting = (policy: Policy | undefined): boolean =>
  policy === undefined || policy === ClientTrafficPolicy.None;

/** Label shown instead of the routing switch when the administrator decided the routing. */
export const lockedRoutingLabel = (policy: Policy | undefined): string | null => {
  switch (policy) {
    case ClientTrafficPolicy.ForceAllTraffic:
      return 'All traffic is routed through the VPN (set by your administrator)';
    case ClientTrafficPolicy.DisableAllTraffic:
      return 'Only predefined traffic is routed (set by your administrator)';
    default:
      return null;
  }
};
