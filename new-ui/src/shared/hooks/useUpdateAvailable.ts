import { useQuery } from '@tanstack/react-query';
import { getVersion } from '@tauri-apps/api/app';

import { getLatestAppVersionQueryOptions } from '../rust-api/query';
import type { NewAppVersionInfo } from '../rust-api/types';
import { isVersionGreater } from '../utils/compareVersions';

export const isUpdateAvailable = (
  latest: NewAppVersionInfo | null | undefined,
  currentVersion: string | undefined,
): boolean =>
  latest !== undefined &&
  latest !== null &&
  currentVersion !== undefined &&
  isVersionGreater(latest.version, currentVersion);

export const useUpdateAvailable = (): boolean => {
  const { data: latest } = useQuery(getLatestAppVersionQueryOptions);
  const { data: currentVersion } = useQuery({
    queryKey: ['app-version'] as const,
    queryFn: () => getVersion(),
  });

  return isUpdateAvailable(latest, currentVersion);
};
