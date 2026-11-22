//! CTAP2 over USB HID (Linux, macOS), through `ctap-hid-fido2`. Blocking: run on a blocking
//! thread.
//!
//! `ctap-hid-fido2` hashes the "challenge" it is given into the client data hash, so it is handed
//! the canonical client data itself and the key signs `SHA-256(clientData)` as WebAuthn expects.

use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory, LibCfg,
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};

use super::{
    Assertion, Fido2Error,
    protocol::{CreationOptions, map_device_error},
};

fn open_key() -> Result<FidoKeyHid, Fido2Error> {
    let mut cfg = LibCfg::init();
    // The library would print "touch the sensor" to stdout; the UI shows its own prompt.
    cfg.enable_keep_alive_msg = false;
    let mut key =
        FidoKeyHidFactory::create(&cfg).map_err(|err| map_device_error(&err.to_string()))?;
    key.set_pin_uv_auth_protocol_two()
        .map_err(|err| map_device_error(&err.to_string()))?;
    Ok(key)
}

/// Signs `client_data` with one of `credential_ids` for `rp_id`, with the PIN (user
/// verification) and a touch (user presence).
pub(super) fn get_assertion(
    rp_id: &str,
    client_data: &[u8],
    credential_ids: &[Vec<u8>],
    pin: &str,
) -> Result<Assertion, Fido2Error> {
    let key = open_key()?;
    let mut args = GetAssertionArgsBuilder::new(rp_id, client_data).pin(pin);
    for id in credential_ids {
        args = args.add_credential_id(id);
    }
    let assertions = key
        .get_assertion_with_args(&args.build())
        .map_err(|err| map_device_error(&err.to_string()))?;
    let assertion = assertions
        .into_iter()
        .next()
        .ok_or(Fido2Error::NoCredentials)?;
    // A key that holds exactly one allowed credential may leave the ID out of its answer.
    let credential_id = if assertion.credential_id.is_empty() && credential_ids.len() == 1 {
        credential_ids[0].clone()
    } else {
        assertion.credential_id
    };
    if !assertion.flags.user_present_result || !assertion.flags.user_verified_result {
        return Err(Fido2Error::NotAllowed);
    }
    Ok(Assertion {
        credential_id,
        authenticator_data: assertion.auth_data,
        signature: assertion.signature,
    })
}

/// Creates a credential from parsed creation options, returning the credential ID and the
/// authenticator data.
pub(super) fn make_credential(
    options: &CreationOptions,
    client_data: &[u8],
    pin: &str,
) -> Result<(Vec<u8>, Vec<u8>), Fido2Error> {
    let key = open_key()?;
    let user = PublicKeyCredentialUserEntity::new(
        Some(&options.user_id),
        Some(&options.user_name),
        Some(&options.user_display_name),
    );
    let mut args = MakeCredentialArgsBuilder::new(&options.rp_id, client_data)
        .pin(pin)
        .user_entity(&user);
    for id in &options.exclude {
        args = args.exclude_authenticator(id);
    }
    let attestation = key
        .make_credential_with_args(&args.build())
        .map_err(|err| map_device_error(&err.to_string()))?;
    if !attestation.flags.user_present_result || !attestation.flags.user_verified_result {
        return Err(Fido2Error::NotAllowed);
    }
    if attestation.credential_descriptor.id.is_empty() || attestation.auth_data.is_empty() {
        return Err(Fido2Error::Device(
            "the key returned no credential".to_owned(),
        ));
    }
    Ok((attestation.credential_descriptor.id, attestation.auth_data))
}
