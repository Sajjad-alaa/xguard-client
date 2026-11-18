import { platform } from '@tauri-apps/plugin-os';

/** Windows runs the ceremony through the platform WebAuthn API, which collects the PIN itself.
 *  Mirrors `pin_policy()` in `src-tauri/src/security_key.rs`. */
export const fido2CollectsPinInApp = (): boolean => platform() !== 'windows';

/** A platform that runs the ceremony shows its own modal, and ours would render behind it. */
export const fido2ShowsTouchPrompt = (): boolean => fido2CollectsPinInApp();
