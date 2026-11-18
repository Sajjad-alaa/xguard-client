/** Shown when the administrator changed a location the user is connected to and the tunnel
 * needs a manual reconnect (MFA locations cannot reconnect on their own). */
export const configChangedMessage = (instanceName: string): string =>
  `The configuration of ${instanceName} changed. Reconnect to apply it.`;
