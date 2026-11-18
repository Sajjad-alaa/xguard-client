import { describe, expect, it } from 'vitest';
import { ClientTrafficPolicy } from '../rust-api/types';
import {
  canChooseRouting,
  effectiveRouteAllTraffic,
  lockedRoutingLabel,
} from './trafficPolicy';

describe('client traffic policy', () => {
  it('keeps the user choice without a policy', () => {
    for (const policy of [undefined, ClientTrafficPolicy.None]) {
      expect(effectiveRouteAllTraffic(policy, true)).toBe(true);
      expect(effectiveRouteAllTraffic(policy, false)).toBe(false);
      expect(canChooseRouting(policy)).toBe(true);
      expect(lockedRoutingLabel(policy)).toBeNull();
    }
  });

  it('overrides the user choice when the administrator decides', () => {
    expect(effectiveRouteAllTraffic(ClientTrafficPolicy.ForceAllTraffic, false)).toBe(
      true,
    );
    expect(effectiveRouteAllTraffic(ClientTrafficPolicy.DisableAllTraffic, true)).toBe(
      false,
    );
    for (const policy of [
      ClientTrafficPolicy.ForceAllTraffic,
      ClientTrafficPolicy.DisableAllTraffic,
    ]) {
      expect(canChooseRouting(policy)).toBe(false);
      expect(lockedRoutingLabel(policy)).toContain('administrator');
    }
  });
});
