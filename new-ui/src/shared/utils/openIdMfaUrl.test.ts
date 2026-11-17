import { describe, expect, it } from 'vitest';
import { buildOpenIdMfaUrl } from './openIdMfaUrl';

// Edge serves the OpenID MFA page at `<edge>/openid/mfa` and joins the token and attempt ID
// into the session reference Core binds the browser sign-in to.
describe('buildOpenIdMfaUrl', () => {
  it('points multi-step sessions at the attempt being completed', () => {
    const url = buildOpenIdMfaUrl('https://edge.example.org', 'tok123', 'att456');
    expect(url.origin).toBe('https://edge.example.org');
    expect(url.pathname).toBe('/openid/mfa');
    expect(url.searchParams.get('token')).toBe('tok123');
    expect(url.searchParams.get('step_attempt_id')).toBe('att456');
  });

  it('omits the attempt for legacy sessions', () => {
    const url = buildOpenIdMfaUrl('https://edge.example.org/', 'tok123', null);
    expect(url.pathname).toBe('/openid/mfa');
    expect(url.searchParams.has('step_attempt_id')).toBe(false);
  });

  it('keeps a path prefix of the Edge URL', () => {
    const url = buildOpenIdMfaUrl('https://example.org/vpn', 'tok123', null);
    expect(url.pathname).toBe('/vpn/openid/mfa');
  });
});
