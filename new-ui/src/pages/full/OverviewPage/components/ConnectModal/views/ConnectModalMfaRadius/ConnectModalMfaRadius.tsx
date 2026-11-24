import './style.scss';
import { useCallback, useEffect, useState } from 'react';
import { useShallow } from 'zustand/shallow';
import { Button } from '../../../../../../../shared/components/Button/Button';
import { ButtonVariant } from '../../../../../../../shared/components/Button/types';
import { Controls } from '../../../../../../../shared/components/Controls/Controls';
import { IconKind } from '../../../../../../../shared/components/Icon';
import { InfoBanner } from '../../../../../../../shared/components/InfoBanner/InfoBanner';
import { Input } from '../../../../../../../shared/components/Input/Input';
import { useMfaConnect } from '../../../../../../../shared/components/LocationCard/hooks/useMfaConnect';
import { SizedBox } from '../../../../../../../shared/components/SizedBox/SizedBox';
import { type LocationInfo, MfaMethod } from '../../../../../../../shared/rust-api/types';
import { ThemeSpacing } from '../../../../../../../shared/types';
import { ConnectModalPostureCheckLoading } from '../../components/ConnectModalPostureCheckLoading/ConnectModalPostureCheckLoading';
import { ConnectModalView } from '../../hooks/types';
import { useConnectModal } from '../../hooks/useConnectModal';
import { useMfaStep } from '../../hooks/useMfaStep';

const MIN_POSTURE_LOADER_MS = 500;

export const ConnectModalMfaRadius = () => {
  const [perviousView, location] = useConnectModal(
    useShallow((s) => [s.perviousView, s.location]),
  );

  const { canPickOtherMethod, stepPlan, mfaToken, setMfaToken, goToStep } = useMfaStep();

  const {
    verifyCode,
    isVerifying,
    verifyError,
    isStarting,
    startError,
    radiusChallenge,
  } = useMfaConnect(location as LocationInfo, MfaMethod.Radius, {
    stepPlan,
    mfaToken,
    setMfaToken,
    onStepAdvanced: goToStep,
    debounceMs: location?.posture_check_required ? MIN_POSTURE_LOADER_MS : 0,
    onSessionExpired: () =>
      useConnectModal.getState().setView(perviousView ?? ConnectModalView.MfaSettings),
    onPostureError: (err) => {
      useConnectModal.setState({ postureError: err });
      useConnectModal.getState().setView(ConnectModalView.PostureCheckFail);
    },
    onServiceUnavailable: () =>
      useConnectModal.getState().setView(ConnectModalView.ConnectionError),
  });

  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    (overrideCode?: string) => {
      const value = (overrideCode ?? code).trim();
      setError(null);
      void verifyCode(value);
    },
    [code, verifyCode],
  );

  useEffect(() => {
    if (verifyError) setError(verifyError);
  }, [verifyError]);

  useEffect(() => {
    if (radiusChallenge) {
      setCode('');
      setError(null);
    }
  }, [radiusChallenge]);

  useEffect(() => {
    if (!radiusChallenge?.push) return;
    const intervalMs = Math.max(1, radiusChallenge.pollIntervalSecs) * 1000;
    const timer = window.setInterval(() => {
      void verifyCode(null);
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [radiusChallenge?.push, radiusChallenge?.pollIntervalSecs, verifyCode]);

  if (isStarting && location?.posture_check_required && !startError) {
    return <ConnectModalPostureCheckLoading />;
  }

  return (
    <div id="mfa-radius-view">
      <p className="view-description">
        Enter your RADIUS one-time code, or trigger an SMS / push approval challenge.
      </p>
      {radiusChallenge && (
        <>
          <InfoBanner
            icon={IconKind.InfoFilled}
            message={
              radiusChallenge.message ||
              (radiusChallenge.push
                ? 'Approve the sign-in request on your device, or enter a code below.'
                : 'Enter the challenge response from your RADIUS provider.')
            }
          />
          {radiusChallenge.push && (
            <>
              <SizedBox height={ThemeSpacing.Sm} />
              <div className="radius-push-status" role="status" aria-live="polite">
                <span className="pulse-dot" aria-hidden="true" />
                <span>Waiting for push approval — polling automatically…</span>
              </div>
            </>
          )}
          <SizedBox height={ThemeSpacing.Md} />
        </>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSubmit();
        }}
      >
        <Input
          label="RADIUS code / PIN+OTP"
          placeholder="Enter code or leave blank for challenge"
          value={code}
          error={startError ?? error ?? undefined}
          disabled={isStarting || isVerifying}
          onChange={(val) => {
            setCode(val == null ? '' : String(val));
            setError(null);
          }}
        />
        {!radiusChallenge?.push && (
          <>
            <SizedBox height={ThemeSpacing.Sm} />
            <div className="radius-trigger-row">
              <Button
                text="Send SMS / Push challenge"
                variant={ButtonVariant.Outlined}
                disabled={isStarting || isVerifying}
                onClick={() => handleSubmit('')}
              />
            </div>
          </>
        )}
        <SizedBox height={ThemeSpacing.Md} />
        <Controls>
          {canPickOtherMethod && (
            <Button
              variant={ButtonVariant.Secondary}
              text="Other methods"
              onClick={() => {
                useConnectModal.getState().setView(ConnectModalView.MfaSettings);
              }}
            />
          )}
          <div className="right">
            <Button
              text="Verify"
              variant={ButtonVariant.Primary}
              onClick={() => handleSubmit()}
              loading={isStarting || isVerifying}
            />
          </div>
        </Controls>
      </form>
    </div>
  );
};
