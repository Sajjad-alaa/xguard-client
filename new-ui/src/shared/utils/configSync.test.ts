import { describe, expect, it } from 'vitest';
import { configChangedMessage } from './configSync';

describe('configChangedMessage', () => {
  it('names the instance and asks for a reconnect', () => {
    const message = configChangedMessage('Office');
    expect(message).toContain('Office');
    expect(message).toContain('Reconnect');
  });
});
