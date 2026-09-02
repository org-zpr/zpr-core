//! OIDC Relying Party flow for ph-cli (org-zpr/zpr-core#1390, plan item D3).
//!
//! Implements the OAuth 2.0 authorization-code flow with PKCE (RFC 7636,
//! S256 only) against an OIDC provider, using a single-use loopback HTTP
//! listener as the redirect target. The entry point is [`login`], which is
//! used standalone by the hidden `ph-cli oidc-login` debug subcommand and
//! will be wired behind the packet handler's `AuthAgent` interface when the
//! D2 plan item lands.
//!
//! Security invariants:
//! - The authorization `code`, the `id_token`, and the PKCE `verifier` are
//!   never printed or logged. Progress messages carry the issuer and the
//!   authorization URL only (the URL contains the one-way S256 challenge,
//!   not the verifier).
//! - The redirect listener binds 127.0.0.1 only, accepts exactly one
//!   request, and validates the `state` parameter before releasing the code.

use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// Errors from the OIDC relying-party flow.
#[derive(Debug, thiserror::Error)]
pub enum OidcCliError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error talking to the IdP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("state parameter mismatch in authorization redirect")]
    StateMismatch,
    #[error("timed out waiting for the authorization callback")]
    Timeout,
    #[error("malformed authorization callback: {0}")]
    BadCallback(String),
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    #[error("failed to launch browser: {0}")]
    Browser(String),
    #[error("non-interactive OIDC login is not supported yet")]
    NonInteractiveUnsupported,
}

/// Description of an OIDC identity provider a link may authenticate against.
///
/// Field set matches Contract "OidcIdpInfo" in the OIDC master plan
/// (docs/plans/2026-09-02-oidc-implementation-plan.md); when the D2 plan item
/// lands this type is expected to move to (or be re-exported from) the
/// packet-handler side.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcIdpInfo {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_offline_access: bool,
}

/// A PKCE verifier/challenge pair (RFC 7636, S256 method).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// RFC 7636 S256: 32 random bytes -> base64url-nopad verifier (43 chars);
/// challenge = base64url-nopad(SHA-256(verifier)).
pub fn pkce_s256() -> Pkce {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = pkce_challenge_for(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// Compute the S256 challenge for a given verifier (exposed for the RFC 7636
/// appendix-B test vector).
pub fn pkce_challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The two endpoints we need from the provider's discovery document.
pub struct Discovery {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
}

/// Fetch `<issuer>/.well-known/openid-configuration` and extract the
/// authorization and token endpoints.
pub async fn discover(issuer: &Url, http: &reqwest::Client) -> Result<Discovery, OidcCliError> {
    let base = issuer.as_str().trim_end_matches('/');
    let doc_url = format!("{base}/.well-known/openid-configuration");
    let resp = http.get(&doc_url).send().await?;
    if !resp.status().is_success() {
        return Err(OidcCliError::Discovery(format!(
            "{} returned HTTP {}",
            doc_url,
            resp.status()
        )));
    }
    let doc: serde_json::Value = resp.json().await?;
    let field = |name: &str| -> Result<Url, OidcCliError> {
        let raw = doc
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcCliError::Discovery(format!("missing `{name}`")))?;
        Ok(Url::parse(raw)?)
    };
    Ok(Discovery {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
    })
}

/// Bind a fresh loopback listener on 127.0.0.1 with an OS-assigned port and
/// return it together with the redirect URI `http://127.0.0.1:<port>/callback`.
///
/// Must be called from within a tokio runtime (the std listener is converted
/// to a tokio one).
pub fn bind_loopback() -> Result<(TcpListener, Url), OidcCliError> {
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let port = listener.local_addr()?.port();
    let redirect_uri = Url::parse(&format!("http://127.0.0.1:{port}/callback"))?;
    Ok((listener, redirect_uri))
}

/// Accept exactly one HTTP request on `listener`, verify the `state` query
/// parameter matches `expected_state`, answer with a small "you can close
/// this window" page, and return the authorization `code`.
///
/// The listener is consumed: it is closed when this function returns,
/// success or failure, so the redirect endpoint is single-use.
pub async fn await_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    let result = tokio::time::timeout(timeout, async {
        let (mut stream, _peer) = listener.accept().await?;
        let (_method, target, _body) = read_http_request(&mut stream).await?;
        // Parse the request target's query parameters via a dummy base URL.
        let parsed = Url::parse(&format!("http://localhost{target}"))
            .map_err(|e| OidcCliError::BadCallback(e.to_string()))?;
        let mut code = None;
        let mut state = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                _ => {}
            }
        }
        if state.as_deref() != Some(expected_state) {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                "state mismatch",
            )
            .await;
            return Err(OidcCliError::StateMismatch);
        }
        let code =
            code.ok_or_else(|| OidcCliError::BadCallback("missing `code` parameter".to_string()))?;
        write_http_response(
            &mut stream,
            "200 OK",
            "text/html",
            "<html><body><p>Authentication complete. You can close this window.</p></body></html>",
        )
        .await?;
        Ok(code)
    })
    .await;
    // Listener is dropped (closed) here regardless of outcome.
    match result {
        Ok(inner) => inner,
        Err(_elapsed) => Err(OidcCliError::Timeout),
    }
}

/// Exchange the authorization code for an `id_token` at the token endpoint
/// (RFC 6749 section 4.1.3 + RFC 7636 section 4.5). `client_secret` is sent
/// only when the client is confidential.
pub async fn exchange_code(
    token_endpoint: &Url,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    verifier: &str,
    redirect_uri: &Url,
    http: &reqwest::Client,
) -> Result<String, OidcCliError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let resp = http.post(token_endpoint.clone()).form(&form).send().await?;
    let status = resp.status();
    if !status.is_success() {
        // Deliberately do not include the response body: it could echo the code.
        return Err(OidcCliError::TokenExchange(format!("HTTP {status}")));
    }
    let body: serde_json::Value = resp.json().await?;
    body.get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| OidcCliError::TokenExchange("response has no `id_token`".to_string()))
}

/// Run the whole relying-party flow against `idp` and return the `id_token`.
///
/// `open_browser = false` prints the authorization URL instead of launching a
/// browser (CI / `--no-browser`). Progress goes to stderr.
pub async fn login(
    idp: &OidcIdpInfo,
    nonce: &str,
    open_browser: bool,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    login_with_progress(idp, nonce, open_browser, timeout, &mut |msg| {
        eprintln!("{msg}")
    })
    .await
}

/// Agent-facing wrapper matching the D2 `getOidcCredential` contract: the
/// non-interactive path (refresh tokens / `offline_access` / keyring) is a
/// follow-up issue, so `interactive = false` is rejected.
// Not called from the binary until plan item D2 wires the auth-agent; kept
// (and tested) so D2 can consume it as-is.
#[allow(dead_code)]
pub async fn get_oidc_credential(
    idp: &OidcIdpInfo,
    nonce: &str,
    interactive: bool,
    open_browser: bool,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    if !interactive {
        return Err(OidcCliError::NonInteractiveUnsupported);
    }
    login(idp, nonce, open_browser, timeout).await
}

/// [`login`] with an explicit progress sink so tests can capture every
/// message and assert no secret material leaks into it.
pub async fn login_with_progress(
    idp: &OidcIdpInfo,
    nonce: &str,
    open_browser: bool,
    timeout: Duration,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<String, OidcCliError> {
    let issuer = Url::parse(&idp.issuer)?;
    let http = reqwest::Client::new();
    let discovery = discover(&issuer, &http).await?;
    let pkce = pkce_s256();
    let mut state_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut state_bytes);
    let state = URL_SAFE_NO_PAD.encode(state_bytes);
    let (listener, redirect_uri) = bind_loopback()?;

    let mut auth_url = discovery.authorization_endpoint.clone();
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &idp.client_id)
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("scope", &idp.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");

    if open_browser {
        progress(&format!(
            "Authentication with {} required. Opening browser…",
            idp.issuer
        ));
        open_in_browser(auth_url.as_str())?;
    } else {
        progress(&format!(
            "Authentication with {} required. Open this URL to continue: {}",
            idp.issuer, auth_url
        ));
    }

    let code = await_callback(listener, &state, timeout).await?;
    progress("Authorization received; exchanging code for token…");
    let id_token = exchange_code(
        &discovery.token_endpoint,
        &idp.client_id,
        idp.client_secret.as_deref(),
        &code,
        &pkce.verifier,
        &redirect_uri,
        &http,
    )
    .await?;
    progress("Authentication complete.");
    Ok(id_token)
}

/// Launch the platform browser on `url` (no external crate: `xdg-open` on
/// Linux, `open` on macOS).
fn open_in_browser(url: &str) -> Result<(), OidcCliError> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    Command::new(program)
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| OidcCliError::Browser(format!("{program}: {e}")))
}

/// Map a `startLink` / link-authentication failure message to the `connect`
/// exit code contract:
/// 2 user declined, 3 timeout, 4 IdP unreachable, 5 visa service rejected the
/// token, 6 policy denied, 7 device blob rejected, 1 anything else.
pub fn exit_code_for_link_error(msg: &str) -> i32 {
    let m = msg.to_ascii_lowercase();
    if m.contains("declined") || m.contains("denied by user") || m.contains("cancelled") {
        2
    } else if m.contains("timed out") || m.contains("timeout") {
        3
    } else if m.contains("unreachable") || m.contains("idp unavailable") {
        4
    } else if m.contains("token") && (m.contains("reject") || m.contains("invalid")) {
        5
    } else if m.contains("policy") {
        6
    } else if m.contains("blob") {
        7
    } else {
        1
    }
}

/// Map an [`OidcCliError`] from the standalone `oidc-login` flow onto the
/// same exit-code contract.
pub fn exit_code_for_oidc_error(err: &OidcCliError) -> i32 {
    match err {
        OidcCliError::Timeout => 3,
        OidcCliError::Http(_) | OidcCliError::Discovery(_) => 4,
        OidcCliError::TokenExchange(_) => 5,
        _ => 1,
    }
}

/// Read one HTTP/1.1 request from `stream`: returns (method, target, body).
/// Minimal parser sufficient for the loopback callback and the tests' fake
/// IdP; not a general HTTP implementation.
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, Vec<u8>), OidcCliError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(OidcCliError::BadCallback("request too large".to_string()));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(OidcCliError::BadCallback(
                "connection closed mid-request".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("empty request".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("no method".to_string()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("no request target".to_string()))?
        .to_string();
    let content_length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok((method, target, body))
}

/// Write a minimal HTTP/1.1 response and flush it.
async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), OidcCliError> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Find `needle` in `haystack`, returning the start index.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpStream;

    /// RFC 7636 appendix B test vector.
    #[test]
    fn test_pkce_rfc7636_vector() {
        assert_eq!(
            pkce_challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// 32 random bytes base64url-nopad encode to exactly 43 chars from the
    /// unreserved/base64url alphabet, and the challenge matches the verifier.
    #[test]
    fn test_pkce_verifier_length_and_charset() {
        for _ in 0..16 {
            let pkce = pkce_s256();
            assert_eq!(pkce.verifier.len(), 43);
            assert!(
                pkce.verifier
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "unexpected char in verifier"
            );
            assert_eq!(pkce.challenge, pkce_challenge_for(&pkce.verifier));
        }
    }

    /// The redirect listener must be loopback-only with an OS-assigned port,
    /// and the redirect URI must reflect exactly that address.
    #[tokio::test]
    async fn test_bind_loopback_is_127_0_0_1() {
        let (listener, redirect_uri) = bind_loopback().unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_ne!(addr.port(), 0);
        assert_eq!(
            redirect_uri.as_str(),
            format!("http://127.0.0.1:{}/callback", addr.port())
        );
    }

    /// A callback with the wrong `state` is rejected and the listener is
    /// closed afterwards (single-use endpoint).
    #[tokio::test]
    async fn test_callback_rejects_state_mismatch() {
        let (listener, redirect_uri) = bind_loopback().unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            await_callback(listener, "expected-state", Duration::from_secs(5)).await
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET /callback?code=x&state=wrong HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let result = task.await.unwrap();
        assert!(matches!(result, Err(OidcCliError::StateMismatch)));
        drop(stream);
        // The listener must be gone: a fresh connection is refused.
        let reconnect = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            reconnect.is_err(),
            "listener still accepting after state mismatch; redirect_uri was {redirect_uri}"
        );
    }

    /// A callback with the matching `state` yields the code exactly once.
    #[tokio::test]
    async fn test_callback_accepts_matching_state_once() {
        let (listener, _redirect_uri) = bind_loopback().unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            await_callback(listener, "good-state", Duration::from_secs(5)).await
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(
                b"GET /callback?code=the-auth-code&state=good-state HTTP/1.1\r\nHost: l\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains("close this window"));
        let code = task.await.unwrap().unwrap();
        assert_eq!(code, "the-auth-code");
        // Single-use: the port no longer accepts connections.
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    /// The token exchange must POST the PKCE verifier and send
    /// `client_secret` only when the client is confidential.
    #[tokio::test]
    async fn test_exchange_code_posts_verifier_and_optional_secret() {
        for secret in [None, Some("s3cret")] {
            let captured = run_token_stub_and_exchange(secret).await;
            let fields: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(captured.as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["code"], "code-abc");
            assert_eq!(fields["code_verifier"], "verifier-xyz");
            assert_eq!(fields["client_id"], "client-1");
            assert!(fields["redirect_uri"].starts_with("http://127.0.0.1:"));
            match secret {
                Some(s) => assert_eq!(fields["client_secret"], s),
                None => assert!(
                    !fields.contains_key("client_secret"),
                    "client_secret sent for a public client"
                ),
            }
        }
    }

    /// Run a one-shot token-endpoint stub, call `exchange_code` against it,
    /// and return the raw form body the stub captured.
    async fn run_token_stub_and_exchange(secret: Option<&str>) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (method, target, body) = read_http_request(&mut stream).await.unwrap();
            assert_eq!(method, "POST");
            assert_eq!(target, "/token");
            write_http_response(
                &mut stream,
                "200 OK",
                "application/json",
                "{\"id_token\":\"tok\"}",
            )
            .await
            .unwrap();
            tx.send(String::from_utf8(body).unwrap()).unwrap();
        });
        let token_endpoint = Url::parse(&format!("http://{addr}/token")).unwrap();
        let redirect_uri = Url::parse(&format!("http://127.0.0.1:{}/callback", 12345)).unwrap();
        let http = reqwest::Client::new();
        let token = exchange_code(
            &token_endpoint,
            "client-1",
            secret,
            "code-abc",
            "verifier-xyz",
            &redirect_uri,
            &http,
        )
        .await
        .unwrap();
        assert_eq!(token, "tok");
        rx.await.unwrap()
    }

    const FAKE_ID_TOKEN: &str = "fake.header.payload";
    const FAKE_CODE: &str = "authcode-8d1e2f";

    /// State a fake IdP records about the requests it served.
    #[derive(Default)]
    struct IdpSeen {
        auth_nonce: Option<String>,
    }

    /// Minimal in-process IdP: serves the discovery document, an `/auth`
    /// endpoint that 302-redirects back with a fixed code and the caller's
    /// `state`, and a `/token` endpoint returning a fixed `id_token`.
    async fn run_fake_idp(listener: TcpListener, seen: Arc<Mutex<IdpSeen>>) {
        let base = format!("http://{}", listener.local_addr().unwrap());
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Ok((_method, target, _body)) = read_http_request(&mut stream).await else {
                continue;
            };
            if target.starts_with("/.well-known/openid-configuration") {
                let body = format!(
                    "{{\"authorization_endpoint\":\"{base}/auth\",\"token_endpoint\":\"{base}/token\"}}"
                );
                let _ = write_http_response(&mut stream, "200 OK", "application/json", &body).await;
            } else if target.starts_with("/auth") {
                let parsed = Url::parse(&format!("http://localhost{target}")).unwrap();
                let mut state = String::new();
                let mut redirect_uri = String::new();
                for (k, v) in parsed.query_pairs() {
                    match k.as_ref() {
                        "state" => state = v.into_owned(),
                        "redirect_uri" => redirect_uri = v.into_owned(),
                        "nonce" => seen.lock().unwrap().auth_nonce = Some(v.into_owned()),
                        _ => {}
                    }
                }
                let location = format!("{redirect_uri}?code={FAKE_CODE}&state={state}");
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else if target.starts_with("/token") {
                let body = format!("{{\"id_token\":\"{FAKE_ID_TOKEN}\"}}");
                let _ = write_http_response(&mut stream, "200 OK", "application/json", &body).await;
            } else {
                let _ = write_http_response(&mut stream, "404 Not Found", "text/plain", "no").await;
            }
        }
    }

    /// Full `--no-browser` flow against the fake IdP. The test plays the
    /// browser: it grabs the printed authorization URL, follows the 302, and
    /// hits the loopback callback. Asserts the nonce reached `/auth` and that
    /// no progress message leaked the code or the token.
    #[tokio::test]
    async fn test_login_no_browser_end_to_end_against_fake_idp() {
        let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let idp_addr = idp_listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(IdpSeen::default()));
        tokio::spawn(run_fake_idp(idp_listener, seen.clone()));

        let idp = OidcIdpInfo {
            issuer: format!("http://{idp_addr}"),
            client_id: "client-1".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            allow_offline_access: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let login_task = tokio::spawn(async move {
            let mut sink = move |m: &str| {
                let _ = tx.send(m.to_string());
            };
            login_with_progress(&idp, "nonce-123", false, Duration::from_secs(10), &mut sink).await
        });

        // Wait for the progress message carrying the authorization URL.
        let mut messages: Vec<String> = Vec::new();
        let auth_url = loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no progress message")
                .expect("progress channel closed");
            messages.push(msg.clone());
            // The URL is the last whitespace-separated token of the
            // "Open this URL to continue:" message.
            if msg.contains("Open this URL") {
                break msg.split_whitespace().last().unwrap().to_string();
            }
        };

        // Play the browser: GET the auth URL (no redirect following), then
        // follow the Location header to the loopback callback.
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let auth_resp = browser.get(&auth_url).send().await.unwrap();
        assert_eq!(auth_resp.status().as_u16(), 302);
        let location = auth_resp.headers()["location"]
            .to_str()
            .unwrap()
            .to_string();
        let cb_resp = browser.get(&location).send().await.unwrap();
        assert!(cb_resp.status().is_success());

        let id_token = login_task.await.unwrap().unwrap();
        assert_eq!(id_token, FAKE_ID_TOKEN);
        assert_eq!(
            seen.lock().unwrap().auth_nonce.as_deref(),
            Some("nonce-123")
        );

        // Drain remaining progress messages, then assert no secret leaked.
        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }
        for msg in &messages {
            assert!(!msg.contains(FAKE_ID_TOKEN), "id_token leaked: {msg}");
            assert!(!msg.contains(FAKE_CODE), "authorization code leaked: {msg}");
        }
    }

    /// The non-interactive agent path is a follow-up issue and must be
    /// rejected explicitly.
    #[tokio::test]
    async fn test_non_interactive_is_unsupported() {
        let idp = OidcIdpInfo {
            issuer: "http://127.0.0.1:1/".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            scopes: vec![],
            allow_offline_access: false,
        };
        let result = get_oidc_credential(&idp, "n", false, false, Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(OidcCliError::NonInteractiveUnsupported)
        ));
    }

    /// The seven `connect` failure classes map onto exit codes 2-7 (and 1
    /// for anything unrecognized).
    #[test]
    fn test_exit_code_mapping() {
        assert_eq!(exit_code_for_link_error("user declined authentication"), 2);
        assert_eq!(exit_code_for_link_error("authentication timed out"), 3);
        assert_eq!(exit_code_for_link_error("IdP unreachable"), 4);
        assert_eq!(exit_code_for_link_error("visa service rejected token"), 5);
        assert_eq!(exit_code_for_link_error("policy denied"), 6);
        assert_eq!(exit_code_for_link_error("device blob rejected"), 7);
        assert_eq!(exit_code_for_link_error("something else entirely"), 1);

        assert_eq!(exit_code_for_oidc_error(&OidcCliError::Timeout), 3);
        assert_eq!(
            exit_code_for_oidc_error(&OidcCliError::Discovery("x".into())),
            4
        );
        assert_eq!(
            exit_code_for_oidc_error(&OidcCliError::TokenExchange("x".into())),
            5
        );
        assert_eq!(exit_code_for_oidc_error(&OidcCliError::StateMismatch), 1);
    }
}
