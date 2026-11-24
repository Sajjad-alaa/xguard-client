import { describe, expect, it } from 'vitest';
import {
  isInvalidCode,
  isRadiusAwaiting,
  mfaErrorMessage,
  parseRadiusChallenge,
} from './mfaError';

describe('isInvalidCode', () => {
  it('matches exact rejected-code messages without case sensitivity', () => {
    expect(isInvalidCode('Unauthorized')).toBe(true);
    expect(isInvalidCode(' unauthorized ')).toBe(true);
    expect(isInvalidCode('invalid code')).toBe(true);
    expect(isInvalidCode(' Invalid Code ')).toBe(true);
  });

  it('does not treat rejection details as retryable code messages', () => {
    expect(isInvalidCode('invalid code: session expired')).toBe(false);
    expect(isInvalidCode('invalid token')).toBe(false);
  });
});

describe('mfaErrorMessage', () => {
  it('maps the outdated mobile client type to an upgrade message', () => {
    expect(mfaErrorMessage(JSON.stringify({ type: 'mobile_client_outdated' }))).toBe(
      'Your XGuard mobile app is out of date.\nUpgrade to approve this connection.',
    );
  });

  it('preserves other error messages and plain text', () => {
    expect(
      mfaErrorMessage(JSON.stringify({ type: 'other', message: 'Existing error' })),
    ).toBe('Existing error');
    expect(mfaErrorMessage('Plain error')).toBe('Plain error');
  });

  it('maps device and connection limit errors to clear user messages', () => {
    expect(mfaErrorMessage(JSON.stringify({ type: 'device_limit_reached' }))).toContain(
      'Maximum number of registered devices reached',
    );
    expect(
      mfaErrorMessage(
        JSON.stringify({
          type: 'other',
          message: 'Concurrent connection limit reached for this user',
        }),
      ),
    ).toContain('Maximum number of concurrent VPN connections reached');
  });
});

describe('RADIUS challenge helpers', () => {
  it('parses radius_challenge payloads with defaults', () => {
    expect(
      parseRadiusChallenge(
        JSON.stringify({
          kind: 'radius_challenge',
          message: 'Enter SMS code',
          push: true,
          pollIntervalSecs: 3,
        }),
      ),
    ).toEqual({
      kind: 'radius_challenge',
      message: 'Enter SMS code',
      push: true,
      pollIntervalSecs: 3,
    });
    expect(parseRadiusChallenge(JSON.stringify({ type: 'other' }))).toBeNull();
  });

  it('detects radius_awaiting responses', () => {
    expect(isRadiusAwaiting(JSON.stringify({ kind: 'radius_awaiting' }))).toBe(true);
    expect(isRadiusAwaiting(JSON.stringify({ kind: 'radius_challenge' }))).toBe(false);
  });
});
