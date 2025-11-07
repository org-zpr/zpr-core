use openssl::x509::X509;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::error;

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

/// Get the CN value as a string out of the certificate. If not found or any
/// other issue, returns None.
pub fn get_cn_from_cert(cert: &X509) -> Option<String> {
    let entry_ref_opt = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next();
    if let Some(entry_ref) = entry_ref_opt {
        let sslstr_res = entry_ref.data().as_utf8();
        if let Ok(sslstr) = sslstr_res {
            return Some(sslstr.to_string());
        }
    }
    None
}

/// Load a certificate from a file.
pub fn load_cert(path: &Path) -> Result<X509, ParseError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(ParseError::IOError(e)),
    };
    let cert_pem_data = extract_cert_pem_data(&contents)?;
    match X509::from_pem(cert_pem_data.as_bytes()) {
        Ok(cert) => Ok(cert),
        Err(e) => Err(ParseError::PEMFormatError(e.to_string())),
    }
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
