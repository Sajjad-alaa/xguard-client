import { describe, expect, it, vi } from 'vitest';

vi.mock('@tauri-apps/api/app', () => ({ getVersion: vi.fn() }));
vi.mock('../rust-api/query', () => ({ getLatestAppVersionQueryOptions: {} }));

import { isUpdateAvailable } from './useUpdateAvailable';

const release = (version: string) => ({
  version,
  release_date: '2026-11-21',
  release_notes_url: `https://github.com/Sajjad-alaa/xguard-client/releases/tag/v${version}`,
  update_url: `https://github.com/Sajjad-alaa/xguard-client/releases/tag/v${version}`,
  summary: null,
  notes: null,
});

describe('isUpdateAvailable', () => {
  it('is false while loading, when up to date and when the check found nothing', () => {
    expect(isUpdateAvailable(undefined, '2.2.0')).toBe(false);
    expect(isUpdateAvailable(release('2.3.0'), undefined)).toBe(false);
    // The Rust side answers null when no release exists yet or GitHub is unreachable.
    expect(isUpdateAvailable(null, '2.2.0')).toBe(false);
    expect(isUpdateAvailable(release('2.2.0'), '2.2.0')).toBe(false);
  });

  it('is true for a newer release', () => {
    expect(isUpdateAvailable(release('2.3.0'), '2.2.0')).toBe(true);
    expect(isUpdateAvailable(release('2.2.1'), '2.2.0-beta1')).toBe(true);
  });
});
