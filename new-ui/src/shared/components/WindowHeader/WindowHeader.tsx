import clsx from 'clsx';
import './style.scss';
import { useQuery } from '@tanstack/react-query';
import { useId } from 'react';
import { api } from '../../rust-api/api';
import { isPresent } from '../../utils/isPresent';
import { ConnectionWatcher } from './components/ConnectionWatcher/ConnectionsWatcher';

interface Props {
  variant: 'compact' | 'desktop';
}

export const WindowHeader = ({ variant }: Props) => {
  const { data: appVersion } = useQuery({
    queryFn: api.getClientBuildVersion,
    queryKey: ['client-build-version'],
  });

  const version = () => {
    if (appVersion) {
      return `Version ${appVersion}`;
    }
  };

  return (
    <div id="window-header" className={clsx(`variant-${variant}`)}>
      <LogoIcon size={variant === 'desktop' ? 33 : 48} />
      <div className="info">
        <p className="label">XGuard VPN Client</p>
        {variant === 'compact' && <ConnectionWatcher placement="bottom-start" />}
        {variant === 'desktop' && isPresent(appVersion) && (
          <p className="version">{version()}</p>
        )}
      </div>
      {variant === 'desktop' && (
        <div className="right">
          <ConnectionWatcher placement={'bottom-end'} />
        </div>
      )}
    </div>
  );
};

const LogoIcon = ({ size = 48 }: { size?: number }) => {
  const id = useId();
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
    >
      <rect width="48" height="48" rx="12" fill={`url(#${id})`} />
      <path
        d="M24 10.298 L35.866 17.149 L35.866 30.851 L24 37.702 L12.134 30.851 L12.134 17.149 Z M14.217 18.352 L14.217 29.648 L24 35.296 L33.783 29.648 L33.783 18.352 L24 12.704 Z M17.344 19.238 L28.762 30.656 L30.656 28.762 L19.238 17.344 Z M28.762 17.344 L17.344 28.762 L19.238 30.656 L30.656 19.238 Z"
        fill="#3961DB"
      />
      <defs>
        <linearGradient
          id={id}
          x1="24"
          y1="0"
          x2="24"
          y2="48"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="white" />
          <stop offset="1" stopColor="#D3DDFB" />
        </linearGradient>
      </defs>
    </svg>
  );
};
