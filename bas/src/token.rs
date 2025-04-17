use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Claims, Header, SignWithKey, Token};
use serde_json::json;
use sha2::Sha384;

pub const JWT_LIFETIME_SECONDS: u64 = 86400; // 24 hours

/// Returns JWT in its encoded string form.
pub fn create_token(client_id: &str, attributes: &Vec<(String, String)>) -> String {
    let mut token_claims: Claims = Claims::default();

    token_claims.registered.subject = Some(client_id.into());
    token_claims.registered.issued_at = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    token_claims.registered.expiration = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + JWT_LIFETIME_SECONDS,
    );
    token_claims.registered.issuer = Some("zpr/bas".to_string());
    token_claims.registered.audience = Some("zpr".to_string());

    // All the attributes are stored as "z/<name>" in the private claims.
    // TODO: An improvement would be to put all the tags in a single attribute, say "ztags".
    for tuple in attributes {
        token_claims
            .private
            .insert(format!("z/{}", tuple.0), json!(tuple.1.clone()));
    }

    // TODO: In future we will sign with our private RSA key which will allow the visa service
    //       to verify it.
    let key: Hmac<Sha384> = Hmac::new_from_slice(b"some-secret-placeholder").unwrap();
    let header = Header {
        algorithm: AlgorithmType::Hs384,
        ..Default::default()
    };

    let token = Token::new(header, token_claims)
        .sign_with_key(&key)
        .unwrap();

    String::from(token.as_str())
}

/// Return the claims in the token without regard to signature or header.
/// Note that ZPR attribute "claims" are prefixed with "z/".
pub fn claims_for(tstr: &str) -> Result<BTreeMap<String, String>, jwt::Error> {
    let token: Token<Header, Claims, _> = Token::parse_unverified(tstr)?;
    let claims = token.claims().clone();
    let mut result = BTreeMap::new();

    if claims.registered.audience.is_some() {
        result.insert("aud".to_string(), claims.registered.audience.unwrap());
    }
    if claims.registered.issuer.is_some() {
        result.insert("iss".to_string(), claims.registered.issuer.unwrap());
    }
    if claims.registered.subject.is_some() {
        result.insert("sub".to_string(), claims.registered.subject.unwrap());
    }
    if claims.registered.issued_at.is_some() {
        result.insert(
            "iat".to_string(),
            claims.registered.issued_at.unwrap().to_string(),
        );
    }
    if claims.registered.expiration.is_some() {
        result.insert(
            "exp".to_string(),
            claims.registered.expiration.unwrap().to_string(),
        );
    }
    if claims.registered.not_before.is_some() {
        result.insert(
            "nbf".to_string(),
            claims.registered.not_before.unwrap().to_string(),
        );
    }
    if claims.registered.json_web_token_id.is_some() {
        result.insert(
            "jti".to_string(),
            claims.registered.json_web_token_id.unwrap(),
        );
    }
    for (k, v) in &claims.private {
        match v {
            serde_json::Value::String(s) => {
                result.insert(k.clone(), s.clone());
            }
            serde_json::Value::Number(n) => {
                result.insert(k.clone(), n.to_string());
            }
            _ => {
                result.insert(k.clone(), v.to_string());
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_and_claims_for() {
        let client_id = "test_client_id";
        let attributes = vec![("key1".to_string(), "value1".to_string())];

        let token = create_token(client_id, &attributes);
        let claims = claims_for(&token).unwrap();

        assert_eq!(claims.get("sub").unwrap(), client_id);
        assert_eq!(claims.get("aud").unwrap(), "zpr");
        assert_eq!(claims.get("iss").unwrap(), "zpr/bas");
        assert_eq!(claims.get("z/key1").unwrap(), "value1");
    }
}
