import { describe, expect, it } from 'vitest';
import { getAddInstanceFailure } from './getAddInstanceFailure';

describe('getAddInstanceFailure', () => {
  it('explains that devices are managed by administrators', () => {
    for (const hidden of [true, false]) {
      const failure = getAddInstanceFailure({ errorKind: 'admin_managed' }, hidden);
      expect(failure.kind).toBe('snackbar');
      expect(failure.message).toContain('administrator');
    }
  });

  it('marks the URL field when the instance is unreachable on manual entry', () => {
    expect(getAddInstanceFailure({ errorKind: 'network' }, false)).toEqual({
      kind: 'field',
      field: 'url',
      message: 'Invalid URL.',
    });
  });

  it('marks the token field when the token is rejected on manual entry', () => {
    expect(getAddInstanceFailure({ errorKind: 'unauthorized' }, false)).toEqual({
      kind: 'field',
      field: 'token',
      message: 'Invalid token.',
    });
  });

  it.each(['network', 'unauthorized'] as const)(
    'shows a snackbar for %s errors when the credentials came from a deep link',
    (errorKind) => {
      expect(getAddInstanceFailure({ errorKind }, true).kind).toBe('snackbar');
    },
  );

  it('marks the name field when the device name is taken, even from a deep link', () => {
    expect(getAddInstanceFailure({ errorKind: 'name_taken' }, true)).toEqual({
      kind: 'field',
      field: 'name',
      message: 'Name already used.',
    });
  });

  it('falls back to a generic snackbar for server errors', () => {
    expect(getAddInstanceFailure({ error: 'boom', errorKind: 'server' }, false)).toEqual({
      kind: 'snackbar',
      message: 'Communication error, contact administrator.',
    });
  });
});
