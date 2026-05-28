//! # TLS Record Construction
//!
//! This module exactly replicates the byte-level template-based TLS record
//! construction from the original Python `packet_templates.py`.
//!
//! ## Design Rationale
//!
//! The Python prototype constructs fake TLS ClientHello and ServerHello
//! messages by splicing random fields (random, session_id, key_share) into
//! a static template.  This approach:
//!
//! 1. **Preserves exact JA3 fingerprints** — the template was captured from
//!    a real TLS handshake and every byte matters for DPI evasion.
//! 2. **Minimizes code** — no need for a full TLS library; the template
//!    already encodes the correct cipher suites, extensions, and ordering.
//! 3. **Matches the original exactly** — critical for A/B testing during
//!    migration from Python to Rust.
//!
//! ## Supported Fingerprints
//!
//! The default template matches a Chrome-on-Windows fingerprint.  Future
//! versions will expose factory methods for Firefox, Android, and
//! randomized JA3 fingerprints.

use std::sync::OnceLock;

use bytes::Bytes;
use rand::Rng;

// ---------------------------------------------------------------------------
// TLS record type constants
// ---------------------------------------------------------------------------

/// TLS content type: Change Cipher Spec (0x14)
pub const TLS_CHANGE_CIPHER: u8 = 0x14;

/// TLS content type: Handshake (0x16)
pub const TLS_HANDSHAKE: u8 = 0x16;

/// TLS content type: Application Data (0x17)
pub const TLS_APP_DATA: u8 = 0x17;

/// TLS record version for TLS 1.2 (used in record layer): {0x03, 0x03}
pub const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];

// ---------------------------------------------------------------------------
// ClientHello template (hex-encoded)
//
// Captured from a real Chrome TLS 1.3 handshake.  517 bytes.
// ---------------------------------------------------------------------------

const TLS_CH_TEMPLATE_HEX: &str =
    "1603020200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn ch_template() -> &'static [u8] {
    static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
    TEMPLATE.get_or_init(|| hex::decode(TLS_CH_TEMPLATE_HEX).expect("Invalid CH template hex"))
}

// ---------------------------------------------------------------------------
// ClientHelloBuilder — exact port from Python's ClientHelloMaker class
// ---------------------------------------------------------------------------

/// Constructs fake TLS ClientHello messages using the static template.
///
/// ## Usage
///
/// ```rust
/// use mamadvpn_common::ClientHelloBuilder;
/// use rand::Rng;
///
/// let mut rng = rand::thread_rng();
/// let rnd: [u8; 32] = rng.gen();
/// let sess_id: [u8; 32] = rng.gen();
/// let key_share: [u8; 32] = rng.gen();
/// let sni = b"www.cloudflare.com";
///
/// let client_hello = ClientHelloBuilder::build(rnd, sess_id, sni, key_share);
/// ```
pub struct ClientHelloBuilder;

impl ClientHelloBuilder {
    /// Build a fake TLS ClientHello with the given random fields.
    ///
    /// # Arguments
    ///
    /// * `random` — 32 bytes of random data for the TLS random field.
    /// * `session_id` — 32 bytes for the TLS session ID.
    /// * `sni` — The SNI hostname to insert into the Server Name extension.
    /// * `key_share` — 32 bytes for the TLS 1.3 key share extension data.
    ///
    /// # Returns
    ///
    /// A complete TLS ClientHello record as `Bytes`.
    pub fn build(random: [u8; 32], session_id: [u8; 32], sni: &[u8], key_share: [u8; 32]) -> Bytes {
        let template = ch_template();
        let default_sni = b"mci.ir"; // Python's template_sni

        // Extract static slices matching Python's ClientHelloMaker fields:
        //   static1 = tls_ch_template[:11]
        //   static2 = b"\x20"
        //   static3 = tls_ch_template[76:120]
        //   static4 = tls_ch_template[127+len(template_sni):262+len(template_sni)]
        //   static5 = b"\x00\x15"
        let static1 = &template[..11];
        let static3 = &template[76..120];
        let static4_start = 127 + default_sni.len();
        let static4_end = 262 + default_sni.len();
        let static4 = &template[static4_start..static4_end];

        // ---- Server Name extension (Python equivalent) ----
        // struct.pack("!H", len(sni) + 5) + struct.pack("!H", len(sni) + 3) + b"\x00" + struct.pack("!H", len(sni)) + sni
        let sni_len = sni.len();
        let mut server_name_ext = Vec::with_capacity(sni_len + 5);
        server_name_ext.extend_from_slice(&((sni_len + 5) as u16).to_be_bytes());
        server_name_ext.extend_from_slice(&((sni_len + 3) as u16).to_be_bytes());
        server_name_ext.push(0x00);
        server_name_ext.extend_from_slice(&(sni_len as u16).to_be_bytes());
        server_name_ext.extend_from_slice(sni);

        // ---- Padding extension (Python equivalent) ----
        // struct.pack("!H", 219 - len(sni)) + (b"\x00" * (219 - len(sni)))
        let padding_len = 219usize.wrapping_sub(sni_len);
        let mut padding_ext = Vec::with_capacity(2 + padding_len);
        padding_ext.extend_from_slice(&(padding_len as u16).to_be_bytes());
        padding_ext.resize(2 + padding_len, 0u8);

        // ---- Assemble ----
        let total_size = 11    // static1
            + 32               // random
            + 1                // static2 (0x20)
            + 32               // session_id
            + 44               // static3
            + server_name_ext.len()
            + static4.len()
            + 32               // key_share
            + 2                // static5 (0x00, 0x15)
            + padding_ext.len();

        let mut result = Vec::with_capacity(total_size);
        result.extend_from_slice(static1);
        result.extend_from_slice(&random);
        result.push(0x20); // static2
        result.extend_from_slice(&session_id);
        result.extend_from_slice(static3);
        result.extend_from_slice(&server_name_ext);
        result.extend_from_slice(static4);
        result.extend_from_slice(&key_share);
        result.extend_from_slice(b"\x00\x15"); // static5
        result.extend_from_slice(&padding_ext);

        Bytes::from(result)
    }

    /// Generate a random ClientHello with a given SNI.
    ///
    /// Convenience method filling random, session_id, and key_share with
    /// cryptographically random bytes.
    ///
    /// Equivalent to the Python:
    /// ```python
    /// ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32))
    /// ```
    pub fn generate(sni: &[u8]) -> Bytes {
        let mut rng = rand::thread_rng();
        let random: [u8; 32] = rng.gen();
        let session_id: [u8; 32] = rng.gen();
        let key_share: [u8; 32] = rng.gen();
        Self::build(random, session_id, sni, key_share)
    }
}

// ---------------------------------------------------------------------------
// ServerHelloBuilder — exact port from Python's ServerHelloMaker class
// ---------------------------------------------------------------------------

/// Constructs fake TLS ServerHello messages (for future use).
///
/// The Python prototype included a `ServerHelloMaker` with the same
/// template-based approach.  Preserved for completeness.
pub struct ServerHelloBuilder;

impl ServerHelloBuilder {
    const TLS_SH_TEMPLATE_HEX: &'static str =
        "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e";

    fn sh_template() -> &'static [u8] {
        static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
        TEMPLATE
            .get_or_init(|| hex::decode(Self::TLS_SH_TEMPLATE_HEX).expect("Invalid SH template hex"))
    }

    /// Build a fake TLS ServerHello.
    ///
    /// Python equivalent:
    /// ```python
    /// ServerHelloMaker.get_server_hello_with(rnd, sess_id, key_share, app_data)
    /// ```
    pub fn build(random: [u8; 32], session_id: [u8; 32], key_share: [u8; 32], app_data: &[u8]) -> Bytes {
        let template = Self::sh_template();
        let static1 = &template[..11];
        let static3 = &template[76..95];

        let mut result = Vec::new();
        result.extend_from_slice(static1);
        result.extend_from_slice(&random);
        result.push(0x20);
        result.extend_from_slice(&session_id);
        result.extend_from_slice(static3);
        result.extend_from_slice(&key_share);

        // Change Cipher Spec record
        result.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        // Application Data record
        result.push(0x17);
        result.extend_from_slice(&[0x03, 0x03]);
        result.extend_from_slice(&(app_data.len() as u16).to_be_bytes());
        result.extend_from_slice(app_data);

        Bytes::from(result)
    }
}

// ---------------------------------------------------------------------------
// TLS Record helpers
// ---------------------------------------------------------------------------

/// Wrap raw bytes in a TLS Application Data record.
///
/// Python equivalent:
/// ```python
/// tls_app_data_header + struct.pack("!H", len(data)) + data
/// ```
pub fn wrap_application_data(data: &[u8]) -> Bytes {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(TLS_APP_DATA);
    record.extend_from_slice(&TLS_VERSION_1_2);
    record.extend_from_slice(&(data.len() as u16).to_be_bytes());
    record.extend_from_slice(data);
    Bytes::from(record)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build() {
        let mut rng = rand::thread_rng();
        let rnd: [u8; 32] = rng.gen();
        let sid: [u8; 32] = rng.gen();
        let ks: [u8; 32] = rng.gen();
        let sni = b"mci.ir";

        let ch = ClientHelloBuilder::build(rnd, sid, sni, ks);

        // Verify record type = Handshake (0x16)
        assert_eq!(ch[0], 0x16, "First byte should be Handshake type");
        // Verify the template SNI "mci.ir" is embedded
        assert!(
            ch.windows(6).any(|w| w == b"mci.ir"),
            "SNI 'mci.ir' should be present in the ClientHello"
        );

        // Verify length consistency
        let sni_len = sni.len();
        let padding_len = 219usize.wrapping_sub(sni_len);
        let expected_len = 11 + 32 + 1 + 32 + 44 + (sni_len + 5) + 129 + 32 + 2 + (2 + padding_len);
        assert_eq!(ch.len(), expected_len, "ClientHello total length mismatch");
    }

    #[test]
    fn test_client_hello_with_different_sni() {
        let mut rng = rand::thread_rng();
        let rnd: [u8; 32] = rng.gen();
        let sid: [u8; 32] = rng.gen();
        let ks: [u8; 32] = rng.gen();
        let sni = b"www.cloudflare.com";

        let ch = ClientHelloBuilder::build(rnd, sid, sni, ks);

        assert!(
            ch.windows(sni.len()).any(|w| w == sni),
            "SNI 'www.cloudflare.com' should be present"
        );
    }

    #[test]
    fn test_generate_random() {
        let sni = b"auth.vercel.com";
        let ch1 = ClientHelloBuilder::generate(sni);
        let ch2 = ClientHelloBuilder::generate(sni);

        // Two generations should differ (random fields are random)
        assert_ne!(
            &ch1[11..43],
            &ch2[11..43],
            "Random fields should differ between generations"
        );
    }
}
