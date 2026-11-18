//! The pure part of the security key ceremonies: what goes to the key and what goes back to
//! XGuard Core. No I/O, so it is tested without a key.
//!
//! The key signs `authenticatorData || SHA-256(clientData)`. Core does not receive the client
//! data for an assertion; it rebuilds the same canonical JSON from the challenge it issued and
//! its own origin (`xguard_core::fido2::client_data_json`). The two must stay byte-for-byte
//! identical.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Url;
use serde_json::Value;

use super::Fido2Error;

/// The WebAuthn limit for a credential ID.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// More credentials than any user registers; bounds what an Edge can make us send to the key.
const MAX_CREDENTIALS: usize = 32;
/// Core issues 32-byte challenges (43 base64url characters).
const MIN_CHALLENGE_LEN: usize = 16;
const MAX_CHALLENGE_LEN: usize = 128;
/// COSE ES256, the only algorithm the CTAP backend creates.
const COSE_ES256: i64 = -7;

/// Which ceremony client data is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientDataType {
    Create,
    Get,
}

/// Canonical client data, identical to Core's `client_data_json`.
#[must_use]
pub fn client_data_json(kind: ClientDataType, challenge: &str, origin: &str) -> Vec<u8> {
    let kind = match kind {
        ClientDataType::Create => "webauthn.create",
        ClientDataType::Get => "webauthn.get",
    };
    let quote = |value: &str| Value::from(value).to_string();
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        quote(kind),
        quote(challenge),
        quote(origin),
    )
    .into_bytes()
}

/// The relying party and origin of an XGuard instance: its host and its URL's origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelyingParty {
    pub id: String,
    pub origin: String,
}

impl RelyingParty {
    pub fn for_instance(instance_url: &Url) -> Result<Self, Fido2Error> {
        if !matches!(instance_url.scheme(), "https" | "http") {
            return Err(Fido2Error::MalformedChallenge(
                "the instance URL is not HTTP(S)".into(),
            ));
        }
        let id = instance_url
            .domain()
            .ok_or_else(|| {
                Fido2Error::MalformedChallenge("the instance URL has no domain name".into())
            })?
            .to_owned();
        Ok(Self {
            id,
            origin: instance_url.origin().ascii_serialization(),
        })
    }
}

/// Checks that a challenge is plain base64url of a sensible length.
pub fn validate_challenge(challenge: &str) -> Result<(), Fido2Error> {
    let valid_chars = challenge
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !valid_chars || !(MIN_CHALLENGE_LEN..=MAX_CHALLENGE_LEN).contains(&challenge.len()) {
        return Err(Fido2Error::MalformedChallenge(
            "the challenge is not base64url".into(),
        ));
    }
    Ok(())
}

fn decode_credential_id(id: &str) -> Result<Vec<u8>, Fido2Error> {
    let id = URL_SAFE_NO_PAD
        .decode(id.trim_end_matches('='))
        .map_err(|_| Fido2Error::MalformedChallenge("a credential ID is not base64url".into()))?;
    if id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(Fido2Error::MalformedChallenge(
            "a credential ID has an invalid length".into(),
        ));
    }
    Ok(id)
}

/// Decodes the base64url credential IDs offered for an assertion.
pub fn decode_credential_ids(ids: &[String]) -> Result<Vec<Vec<u8>>, Fido2Error> {
    if ids.is_empty() {
        return Err(Fido2Error::NoCredentials);
    }
    if ids.len() > MAX_CREDENTIALS {
        return Err(Fido2Error::MalformedChallenge(
            "too many credential IDs".into(),
        ));
    }
    ids.iter().map(|id| decode_credential_id(id)).collect()
}

/// What the key needs from WebAuthn creation options (`CreationChallengeResponse`).
#[derive(Debug, Eq, PartialEq)]
pub struct CreationOptions {
    pub rp_id: String,
    pub challenge: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub exclude: Vec<Vec<u8>>,
}

fn str_field<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, Fido2Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| Fido2Error::MalformedChallenge(format!("missing {pointer}")))
}

/// Parses creation options and checks them against the instance the user registers with: the
/// relying party must be the instance's own, so an Edge cannot have the key register for
/// another site.
pub fn parse_creation_options(
    options: &str,
    rp: &RelyingParty,
) -> Result<CreationOptions, Fido2Error> {
    let value: Value = serde_json::from_str(options)
        .map_err(|err| Fido2Error::MalformedChallenge(format!("invalid JSON: {err}")))?;
    let rp_id = str_field(&value, "/publicKey/rp/id")?;
    if rp_id != rp.id {
        return Err(Fido2Error::MalformedChallenge(format!(
            "relying party {rp_id} is not this instance ({})",
            rp.id
        )));
    }
    let challenge = str_field(&value, "/publicKey/challenge")?;
    validate_challenge(challenge)?;
    let user_id = decode_credential_id(str_field(&value, "/publicKey/user/id")?)?;
    let user_name = str_field(&value, "/publicKey/user/name")?;
    let user_display_name = str_field(&value, "/publicKey/user/displayName")?;
    let es256 = value
        .pointer("/publicKey/pubKeyCredParams")
        .and_then(Value::as_array)
        .is_some_and(|params| {
            params
                .iter()
                .any(|param| param.get("alg").and_then(Value::as_i64) == Some(COSE_ES256))
        });
    if !es256 {
        return Err(Fido2Error::MalformedChallenge(
            "ES256 is not an accepted algorithm".into(),
        ));
    }
    let exclude = match value
        .pointer("/publicKey/excludeCredentials")
        .and_then(Value::as_array)
    {
        Some(credentials) if credentials.len() > MAX_CREDENTIALS => {
            return Err(Fido2Error::MalformedChallenge(
                "too many excluded credentials".into(),
            ))
        }
        Some(credentials) => credentials
            .iter()
            .map(|credential| decode_credential_id(str_field(credential, "/id")?))
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    Ok(CreationOptions {
        rp_id: rp_id.to_owned(),
        challenge: challenge.to_owned(),
        user_id,
        user_name: user_name.to_owned(),
        user_display_name: user_display_name.to_owned(),
        exclude,
    })
}

fn cbor_head(major: u8, len: usize) -> Vec<u8> {
    let major = major << 5;
    match len {
        0..=23 => vec![major | len as u8],
        24..=0xff => vec![major | 24, len as u8],
        0x100..=0xffff => {
            let [hi, lo] = (len as u16).to_be_bytes();
            vec![major | 25, hi, lo]
        }
        _ => {
            let mut head = vec![major | 26];
            head.extend_from_slice(&(len as u32).to_be_bytes());
            head
        }
    }
}

fn cbor_text(text: &str) -> Vec<u8> {
    let mut out = cbor_head(3, text.len());
    out.extend_from_slice(text.as_bytes());
    out
}

/// A "none" attestation object around the key's authenticator data, as browsers send when the
/// relying party asks for no attestation.
#[must_use]
pub fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    out.extend(cbor_text("fmt"));
    out.extend(cbor_text("none"));
    out.extend(cbor_text("attStmt"));
    out.push(0xa0);
    out.extend(cbor_text("authData"));
    out.extend(cbor_head(2, auth_data.len()));
    out.extend_from_slice(auth_data);
    out
}

/// The registration response sent back to Core (`RegisterPublicKeyCredential` JSON).
#[must_use]
pub fn registration_response(credential_id: &[u8], auth_data: &[u8], client_data: &[u8]) -> String {
    let id = URL_SAFE_NO_PAD.encode(credential_id);
    serde_json::json!({
        "id": id,
        "rawId": id,
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode(none_attestation_object(auth_data)),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
        },
        "type": "public-key",
        "extensions": {},
    })
    .to_string()
}

/// Maps a CTAP or HID error message to what the user can act on.
#[must_use]
pub fn map_device_error(message: &str) -> Fido2Error {
    let has = |needle: &str| message.contains(needle);
    if has("FIDO device not found") {
        Fido2Error::NoDevice
    } else if has("Multiple FIDO devices") {
        Fido2Error::MultipleDevices
    } else if has("PIN_INVALID") {
        Fido2Error::PinInvalid
    } else if has("PIN_BLOCKED") || has("PIN_AUTH_BLOCKED") {
        Fido2Error::PinBlocked
    } else if has("PIN_NOT_SET") || has("PIN_REQUIRED") || has("PUAT_REQUIRED") {
        Fido2Error::PinRequired
    } else if has("NO_CREDENTIALS") {
        Fido2Error::NoCredentials
    } else if has("CREDENTIAL_EXCLUDED") {
        Fido2Error::CredentialExcluded
    } else if has("ACTION_TIMEOUT") || has("ERR_TIMEOUT") {
        Fido2Error::Timeout
    } else if has("OPERATION_DENIED") || has("NOT_ALLOWED") {
        Fido2Error::NotAllowed
    } else if has("KEEPALIVE_CANCEL") {
        Fido2Error::Cancelled
    } else {
        Fido2Error::Device(message.lines().next().unwrap_or_default().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp() -> RelyingParty {
        RelyingParty::for_instance(&Url::parse("https://xguard.example.com/").unwrap()).unwrap()
    }

    #[test]
    fn client_data_matches_core() {
        // The same vector is in Core's `fido2::tests::client_data_is_canonical`.
        assert_eq!(
            client_data_json(
                ClientDataType::Get,
                "q83vEjRWeJA",
                "https://xguard.example.com"
            ),
            br#"{"type":"webauthn.get","challenge":"q83vEjRWeJA","origin":"https://xguard.example.com","crossOrigin":false}"#
        );
        assert_eq!(
            client_data_json(ClientDataType::Create, "a\"b", "https://h:8443"),
            br#"{"type":"webauthn.create","challenge":"a\"b","origin":"https://h:8443","crossOrigin":false}"#
        );
    }

    #[test]
    fn relying_party_comes_from_the_instance_url() {
        assert_eq!(
            rp(),
            RelyingParty {
                id: "xguard.example.com".into(),
                origin: "https://xguard.example.com".into()
            }
        );
        let with_port =
            RelyingParty::for_instance(&Url::parse("https://vpn.example.com:8443/x/").unwrap())
                .unwrap();
        assert_eq!(with_port.id, "vpn.example.com");
        assert_eq!(with_port.origin, "https://vpn.example.com:8443");
        assert!(RelyingParty::for_instance(&Url::parse("https://10.0.0.1/").unwrap()).is_err());
        assert!(RelyingParty::for_instance(&Url::parse("ftp://example.com/").unwrap()).is_err());
    }

    #[test]
    fn challenges_and_credential_ids_are_validated() {
        assert!(validate_challenge("q83vEjRWeJA-_q83vEjRWeJA").is_ok());
        assert!(validate_challenge("short").is_err());
        assert!(validate_challenge("q83vEjRWeJA\"q83vEjRWeJA").is_err());
        assert!(validate_challenge(&"a".repeat(129)).is_err());

        assert_eq!(
            decode_credential_ids(&["AQID".into()]).unwrap(),
            vec![vec![1, 2, 3]]
        );
        assert!(matches!(
            decode_credential_ids(&[]),
            Err(Fido2Error::NoCredentials)
        ));
        assert!(decode_credential_ids(&["not base64!".into()]).is_err());
        assert!(decode_credential_ids(&[URL_SAFE_NO_PAD.encode([0u8; 1024])]).is_err());
        assert!(decode_credential_ids(&vec!["AQID".to_string(); 33]).is_err());
    }

    fn options(rp_id: &str) -> String {
        serde_json::json!({
            "publicKey": {
                "rp": {"id": rp_id, "name": rp_id},
                "user": {"id": "AAEC", "name": "alice", "displayName": "Alice A"},
                "challenge": "q83vEjRWeJA-_q83vEjRWeJA",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "excludeCredentials": [{"type": "public-key", "id": "AQID"}],
                "authenticatorSelection": {"userVerification": "required"},
            }
        })
        .to_string()
    }

    #[test]
    fn creation_options_are_parsed_and_bound_to_the_instance() {
        let parsed = parse_creation_options(&options("xguard.example.com"), &rp()).unwrap();
        assert_eq!(
            parsed,
            CreationOptions {
                rp_id: "xguard.example.com".into(),
                challenge: "q83vEjRWeJA-_q83vEjRWeJA".into(),
                user_id: vec![0, 1, 2],
                user_name: "alice".into(),
                user_display_name: "Alice A".into(),
                exclude: vec![vec![1, 2, 3]],
            }
        );
        assert!(parse_creation_options(&options("evil.example.com"), &rp()).is_err());
        assert!(parse_creation_options("{}", &rp()).is_err());
        let no_es256 = options("xguard.example.com").replace("-7", "-257");
        assert!(parse_creation_options(&no_es256, &rp()).is_err());
    }

    #[test]
    fn registration_response_wraps_auth_data_in_a_none_attestation() {
        let auth_data = vec![7u8; 300];
        let object = none_attestation_object(&auth_data);
        // map(3), "fmt": "none", "attStmt": {}, "authData": bytes(300)
        assert_eq!(&object[..1], &[0xa3]);
        assert_eq!(&object[1..10], b"\x63fmt\x64none");
        assert_eq!(&object[10..19], b"\x67attStmt\xa0");
        assert_eq!(&object[19..28], b"\x68authData");
        assert_eq!(&object[28..31], &[0x59, 0x01, 0x2c]);
        assert_eq!(&object[31..], auth_data.as_slice());

        let response: Value =
            serde_json::from_str(&registration_response(&[1, 2, 3], &auth_data, b"{}")).unwrap();
        assert_eq!(response["id"], "AQID");
        assert_eq!(response["rawId"], "AQID");
        assert_eq!(response["type"], "public-key");
        assert_eq!(response["response"]["clientDataJSON"], "e30");
    }

    #[test]
    fn device_errors_are_mapped() {
        assert!(matches!(
            map_device_error("FIDO device not found."),
            Fido2Error::NoDevice
        ));
        assert!(matches!(
            map_device_error("Multiple FIDO devices found."),
            Fido2Error::MultipleDevices
        ));
        assert!(matches!(
            map_device_error("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
            Fido2Error::PinInvalid
        ));
        assert!(matches!(
            map_device_error("0x32 CTAP2_ERR_PIN_BLOCKED"),
            Fido2Error::PinBlocked
        ));
        assert!(matches!(
            map_device_error("0x35 CTAP2_ERR_PIN_NOT_SET"),
            Fido2Error::PinRequired
        ));
        assert!(matches!(
            map_device_error("0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."),
            Fido2Error::NoCredentials
        ));
        assert!(matches!(
            map_device_error("0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED"),
            Fido2Error::CredentialExcluded
        ));
        assert!(matches!(
            map_device_error("0x2F CTAP2_ERR_USER_ACTION_TIMEOUT"),
            Fido2Error::Timeout
        ));
        assert!(matches!(
            map_device_error("0x27 CTAP2_ERR_OPERATION_DENIED"),
            Fido2Error::NotAllowed
        ));
        assert!(matches!(
            map_device_error("something else\nmore"),
            Fido2Error::Device(message) if message == "something else"
        ));
    }
}
