use std::fs;
use std::path::Path;
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::{Decode, pem};

const PEM_BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("PEM certificate not found in text data")]
    PEMCertNotFound,

    #[error("PEM format error: {0}")]
    PEMFormatError(String),

    #[error("I/O error {0}")]
    IOError(#[from] std::io::Error),
}

/// Isolate the first PEM block
pub fn first_pem_block(text: &str) -> Option<&str> {
    let begin = text.find("-----BEGIN ")?;
    let rest = &text[begin..];
    let end = rest.find("-----END ")?;
    let line_end = rest[end..]
        .find('\n')
        .map(|i| end + i + 1)
        .unwrap_or(rest.len());
    Some(&rest[..line_end])
}

/// Get the CN from DER-encoded certificate
pub fn get_cn_from_cert(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    cert.tbs_certificate()
        .subject()
        .common_name()
        .ok()?
        .map(|cn| cn.value().to_string())
}

/// Load a certificate from a file.
pub fn load_cert(path: &Path) -> Result<Vec<u8>, ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    let (_, der) = pem::decode_vec(cert_pem_data.as_bytes())
        .map_err(|e| ParseError::PEMFormatError(e.to_string()))?;
    Ok(der)
}

/// Look for first instance of "-----BEGIN CERTIFICATE-----" and return that up to and
/// including the "-----END CERTIFICATE-----" line.
///
/// - `textdata` is the textual representation of a certificate that must include the PEM
///    encoded certificate in it somewhere.  Typically, a certificate file has the PEM data
///    at the end.
///
/// Returns a copy of the PEM data from the intput without trying to parse it.
fn extract_cert_pem_data(textdata: &str) -> Result<String, ParseError> {
    let mut pemdata = String::new();
    let mut reading = false;
    for line in textdata.lines() {
        if reading {
            pemdata.push_str(line);
            pemdata.push_str("\n");
            if line.starts_with(PEM_END_CERTIFICATE) {
                return Ok(pemdata);
            }
        } else if line.starts_with(PEM_BEGIN_CERTIFICATE) {
            reading = true;
            pemdata.push_str(line);
            pemdata.push_str("\n");
        }
    }
    if !reading {
        Err(ParseError::PEMCertNotFound)
    } else {
        Err(ParseError::PEMFormatError(
            "failed to parse PEM text".into(),
        ))
    }
}
