import './style.scss';
import { useCallback, useEffect, useState } from 'react';
import { MfaMethod } from '../../../../rust-api/types';
import { ThemeSpacing } from '../../../../types';
import { Button } from '../../../Button/Button';
import { ButtonVariant } from '../../../Button/types';
import { Controls } from '../../../Controls/Controls';
import { Divider } from '../../../Divider/Divider';
import { IconKind } from '../../../Icon';
import { IconButton } from '../../../IconButton/IconButton';
import { IconButtonVariant } from '../../../IconButton/types';
import { InfoBanner } from '../../../InfoBanner/InfoBanner';
import { Input } from '../../../Input/Input';
import { SizedBox } from '../../../SizedBox/SizedBox';
import { LocationViewHeader } from '../../components/LocationViewHeader/LocationViewHeader';
import { useLocationCardContext } from '../../context/context';
import { LocationCardViews } from '../../context/types';
import { useMfaConnect } from '../../hooks/useMfaConnect';
import { LocationCardMfaStartLoader } from '../LocationCardMfaStartLoader/LocationCardMfaStartLoader';

const MIN_POSTURE_LOADER_MS = 500;

export const LocationCardMfaRadiusView = () => {
  const {
    setView,
    showFailure,
    location,
    stepLabel,
    canPickOtherMethod,
    stepPlan,
    mfaToken,
    setMfaToken,
    goToStep,
  } = useLocationCardContext();

  const { verifyCode, isVerifying, verifyError, isStarting, radiusChallenge } =
    useMfaConnect(location, MfaMethod.Radius, {
      stepPlan,
      mfaToken,
      setMfaToken,
      onStepAdvanced: goToStep,
      debounceMs: location.posture_check_required ? MIN_POSTURE_LOADER_MS : 0,
      onConnected: () => setView(LocationCardViews.Connected),
      onFailure: showFailure,
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

  // Automatic push polling while RADIUS server requested push approval.
  useEffect(() => {
    if (!radiusChallenge?.push) return;
    const intervalMs = Math.max(1, radiusChallenge.pollIntervalSecs) * 1000;
    const timer = window.setInterval(() => {
      void verifyCode(null);
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [radiusChallenge?.push, radiusChallenge?.pollIntervalSecs, verifyCode]);

  if (location.posture_check_required && isStarting) {
    return <LocationCardMfaStartLoader />;
  }

  return (
    <div className="location-card-mfa-radius-view">
      <Divider spacing={ThemeSpacing.Md} />
      <LocationViewHeader title={stepLabel ?? 'RADIUS authentication'}>
        <p>
          Enter your RADIUS one-time code, or send a blank challenge to trigger SMS or
          push approval.
        </p>
      </LocationViewHeader>
      <SizedBox height={ThemeSpacing.Md} />
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
          error={error ?? undefined}
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
          <IconButton
            variant={IconButtonVariant.BigSelected}
            icon={IconKind.ArrowBig}
            iconRotation="left"
            onClick={() => {
              setView(LocationCardViews.Default);
            }}
          />
          <div className="right">
            {canPickOtherMethod && (
              <Button
                text="Other methods"
                variant={ButtonVariant.Outlined}
                onClick={() => {
                  setView(LocationCardViews.MfaSettings);
                }}
              />
            )}
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
