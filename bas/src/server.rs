use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::{path::Path, time};

use base64::prelude::*;
use tokio::net::TcpListener;

use crate::fsdb::{CnKey, FsDb};
use crate::token::{JWT_LIFETIME_SECONDS, create_token};

use axum::{
    Json, Router,
    body::Body,
    extract::{Form, Request, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
};

use futures_util::pin_mut;

use tower_service::Service;

use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};

use serde::{Deserialize, Serialize};

use tokio_native_tls::{
    TlsAcceptor,
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
};

use openssl::rand::rand_bytes;

use tracing::{error, info, warn};

/// Sent from the auth service to the adapter. This is the "challenge" part of the
/// authentication protocol. The adapter will use the nonce in a signed message.
#[derive(Debug, Serialize, Default)]
pub struct AdapterAuthRequest {
    pub nonce: String, // base64 encoded bytes
}

/// Sent from the adapter to the auth service as step 2 in the authentication
/// protocol.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AdapterAuthentication {
    pub client_id: String,
    pub nonce: String,   // copied from response to adapter
    pub payload: String, // base64 encoded signature payload created by adapter
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>, // "bearer"
    pub expires_in: Option<u64>,    // seconds
    pub refresh_token: Option<String>,
    pub error: Option<String>, // error code
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AuthRecord {
    client_id: String,
    nonce: String, // base64 encoded bytes
    created: time::Instant,
    code: Option<String>,
    token: Option<String>, // TODO: JWT
}

type SharedState = Arc<RwLock<AppState>>;

#[derive(Debug)]
struct AppState {
    auths: HashMap<String, AuthRecord>, // client_id
    db: FsDb,
}

impl AppState {
    fn new(db: FsDb) -> Self {
        AppState {
            auths: HashMap::new(),
            db,
        }
    }
}

impl AuthRecord {
    fn new(client_id: &str) -> Self {
        AuthRecord {
            client_id: client_id.to_string(),
            nonce: String::new(),
            created: time::Instant::now(),
            code: None,
            token: None,
        }
    }
}

impl AccessTokenResponse {
    fn err(msg: &str) -> Self {
        AccessTokenResponse {
            access_token: None,
            token_type: None,
            expires_in: None,
            refresh_token: None,
            error: Some(msg.to_string()),
        }
    }

    fn is_err(&self) -> bool {
        self.error.is_some()
    }
}

pub async fn start_server(key_file: &Path, cert_file: &Path, db: FsDb) {
    let shared_state = Arc::new(RwLock::new(AppState::new(db)));
    tokio::spawn(start_vs_server(
        native_tls_acceptor(key_file, cert_file),
        3999,
        Arc::clone(&shared_state),
    ));
    start_adapter_server(
        native_tls_acceptor(key_file, cert_file),
        4000,
        Arc::clone(&shared_state),
    )
    .await;
}

fn native_tls_acceptor(key_file: &Path, cert_file: &Path) -> NativeTlsAcceptor {
    let key_pem = std::fs::read_to_string(&key_file).unwrap();
    let cert_pem = std::fs::read_to_string(&cert_file).unwrap();

    let id = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    NativeTlsAcceptor::builder(id)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .unwrap()
}

// Create router for the adapter services. Broken out to ease unit testing.
fn adapter_app(state: SharedState) -> Router {
    Router::new()
        .route(
            "/preauthorize",
            get(authrequest_adapter).with_state(state.clone()),
        )
        .route(
            "/authorize",
            post(authenticate_adapter).with_state(state.clone()),
        )
}

async fn start_adapter_server(acceptor: NativeTlsAcceptor, port: u16, state: SharedState) {
    start_tls_server("adapter services", adapter_app(state), acceptor, port).await;
}

// Create router for the visa-service services. Broken out to ease unit testing.
fn vs_app(state: SharedState) -> Router {
    Router::new().route("/token", post(tokenrequest_vs).with_state(state.clone()))
    // TODO: /refresh
}

async fn start_vs_server(acceptor: NativeTlsAcceptor, port: u16, state: SharedState) {
    start_tls_server("visa service services", vs_app(state), acceptor, port).await;
}

// The scaffolding code here is liberally borrowed from the auxm example:
// https://github.com/tokio-rs/axum/blob/main/examples/low-level-native-tls/src/main.rs
async fn start_tls_server(desc: &str, app: Router, acceptor: NativeTlsAcceptor, port: u16) {
    // TODO: refresh
    let tls_acceptor = TlsAcceptor::from(acceptor);
    let bind = format!("[::1]:{port}"); // TODO:  we don't want to just bind to localhost
    let tcp_listener = TcpListener::bind(bind.clone()).await.unwrap();
    info!("{desc} listening on {bind} (TLS)");

    pin_mut!(tcp_listener);

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();

        let (cnx, addr) = tcp_listener.accept().await.unwrap();
        tokio::spawn(async move {
            let Ok(stream) = tls_acceptor.accept(cnx).await else {
                error!("error during tls handshake from {}", addr);
                return;
            };

            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
                tower_service.clone().call(req)
            });

            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(err) = ret {
                warn!("error serviing connection from {addr}: {err}");
            }
        });
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(dead_code)]
struct TokenRequestInput {
    grant_type: String,
    code: String,
    client_id: String,
    redirect_url: String,
}

// This an OAuth style API used by the visa service to obtain an access token
// given an authorization code.
//
// See RFC6749 section 4.1.3.
//
// Requires form-encoded params:
// - grant_type (must be set to "authorization_code")
// - code (the code returned from adapter authentication)
// - client_id
// - redirect_url (ignored but required)
//
// We return a JSON object.
async fn tokenrequest_vs(
    State(state): State<SharedState>,
    Form(input): Form<TokenRequestInput>,
) -> (StatusCode, Json<AccessTokenResponse>) {
    // The client_id must be in our database, and must have valid token.
    // (TODO: once we have a JWT, check for expiration)
    //
    // Also note that codes are one time use only.

    let auths = &mut state.write().unwrap().auths;

    let resp = match auths.get_mut(&input.client_id) {
        Some(rec) => {
            if rec.code.is_none() || rec.code != Some(input.code.clone()) {
                warn!("tokenrequest for {} but code is invalid", &input.client_id);
                AccessTokenResponse::err("invalid_client")
            } else if rec.token.is_none() {
                warn!("tokenrequest for {} but no token found", &input.client_id);
                AccessTokenResponse::err("invalid_client")
            } else {
                // Code matches, and we have token.
                let resp = AccessTokenResponse {
                    access_token: rec.token.clone(),
                    token_type: Some("bearer".to_string()),
                    expires_in: Some(JWT_LIFETIME_SECONDS),
                    refresh_token: None,
                    error: None,
                };

                // At this point we can remove memory of the auth event.
                auths.remove(&input.client_id);
                info!("tokenrequest for {} succeeds", &input.client_id);
                resp
            }
        }
        None => {
            warn!("tokenrequest for unknown client_id: {}", &input.client_id);
            AccessTokenResponse::err("invalid_client")
        }
    };
    return (
        if resp.is_err() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        },
        Json(resp),
    );
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequestInput {
    response_type: String,
    client_id: String,
    scope: Option<String>,
    state: Option<String>,
}

// This is the OAuth style API used by an adapter to authentiate its actor with
// this authentication service.  This ends up returning a challenge to the
// adapter which it will sign and return in a call to `authenticate_adapter`.
//
// This call does not map exactly onto OAuth.  It is a sort of the first part
// of authorize.  See RFC6745 section 4.1.1.
//
// This expects form encoded params in query string:
// - response_type (must be set to "code")
// - client_id
// - scope (ignored)
// - state (ignored)
//
// Redirect URL (part of OAuth) is not checked and whenever it is used
// it will be set to "https://auth.zpr"
//
// This will create a nonce for this client to use for generating as [AdapterAuthentication].
// We will keep track of the client_id/nonce used.
// async fn authrequest_adapter(req: Request) -> (StatusCode, Json<AdapterAuthRequest>) {
async fn authrequest_adapter(
    State(state): State<SharedState>,
    Form(input): Form<AuthRequestInput>,
) -> (StatusCode, Json<AdapterAuthRequest>) {
    info!("authrequest for {}", input.client_id);

    if input.response_type != "code" {
        warn!(
            "authrequest for {} has invalid response_type {}",
            input.client_id, input.response_type
        );
        return (StatusCode::BAD_REQUEST, Json(AdapterAuthRequest::default()));
    }

    // TODO: how to prevent bad adapter from messing with other clients trying to authenticate?  Maybe limit to once per minute?
    // For now, a request made by a client_id that is already in progress will cancel the existing one.

    let state = &mut state.write().unwrap();
    let Ok(key) = CnKey::from_str(&input.client_id) else {
        error!("error parsing client_id {}", &input.client_id);
        return (StatusCode::BAD_REQUEST, Json(AdapterAuthRequest::default()));
    };

    if !state.db.actor_exists(&key) {
        warn!(
            "authrequest for {} but client_id not in database",
            &input.client_id
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(AdapterAuthRequest::default()),
        );
    }

    if let Some(rec) = state.auths.get(&input.client_id) {
        if rec.code.is_none() {
            warn!(
                "authrequest for {} but auth already in progress, previous is now invalid",
                &input.client_id
            );
        } else {
            info!("new authrequest for {}", &input.client_id);
        }
    }

    let mut rec = AuthRecord::new(&input.client_id);

    let mut buf = [0; 64];
    rand_bytes(&mut buf).unwrap();

    let nonce = BASE64_STANDARD.encode(&buf);
    rec.nonce = nonce.clone();

    state.auths.insert(input.client_id.clone(), rec);

    return (StatusCode::OK, Json(AdapterAuthRequest { nonce }));
}

// This is the OAuth style API used by an adapter to authenticate its actor with
// this authentication service.  This accepts the signature payload from the adapter
// and we will check that it is valid against a public key in our database.
//
// See RFC6749 section 4.1.1 & 4.1.2.
//
// This expects a JSON post data.
//
// We need to check the signature and then return a redirect with
// OAuth style query params:
// - code
//
// Note we don't accept state and don't return it.
//
// Not yet sure if we create the BLOB here or let adapter do it.
//
// According to OAuth, errors are returned encoded in the redirect URL.
async fn authenticate_adapter(
    State(state): State<SharedState>,
    Json(payload): Json<AdapterAuthentication>,
) -> Result<Response, StatusCode> {
    let state = &mut state.write().unwrap();

    let Ok(key) = CnKey::from_str(&payload.client_id) else {
        error!("error parsing client_id {}", &payload.client_id);
        let resp = Response::builder()
            .status(StatusCode::FOUND)
            .header(
                "Location",
                "https://auth.zpr?error=invalid_request&error_description=bad+client_id",
            )
            .body(Body::empty())
            .unwrap();
        return Ok(resp);
    };

    let attrs = state.db.get_attributes(&key).unwrap_or_else(|e| {
        error!("error getting attributes for {}: {}", &payload.client_id, e);
        // Just skip them in this case.
        vec![]
    });

    let mut token: Option<String> = None;

    let location = match state.auths.get_mut(&payload.client_id) {
        Some(rec) => {
            info!("token request for {}", &payload.client_id);
            if (!rec.nonce.is_empty()) && rec.nonce != payload.nonce {
                warn!(
                    "authenticate_adapter for {} but nonce does not match",
                    &payload.client_id
                );
                format!("https://auth.zpr?error=invalid_request&error_description=bad+nonce")
            } else {
                // client_id and nonce are known to us, so we can check the signature

                // TODO: Use the FsDb to load up the public key for this client_id (the CN)
                //       and check the signature.
                info!("faking signature check success for {}", &payload.client_id);

                rec.nonce.clear();
                // The code is secret and only for one time use and should be kept in memory only.
                let code = create_authorization_code();
                let tok = create_token(&payload.client_id, &attrs);
                rec.token = Some(tok.clone());
                token = Some(tok);
                rec.code = Some(format!("{code}"));

                format!("https://auth.zpr?code={}", code)
            }
        }
        None => {
            warn!(
                "authenticate_adapter for {} but no auth in progress",
                &payload.client_id
            );
            format!("https://auth.zpr?error=invalid_request&error_description=not+started") // TODO
        }
    };

    if let Some(tok) = token {
        state.db.add_token(&key, &tok).unwrap_or_else(|e| {
            error!("error adding token to DB for {}: {}", &payload.client_id, e);
        });
    }
    let resp = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap();
    Ok(resp)
}

/// Create random authorization code
fn create_authorization_code() -> u128 {
    let mut buf = [0; 16];
    rand_bytes(&mut buf).unwrap();
    u128::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::claims_for;
    use http_body_util::BodyExt; // for `collect`
    use serde_json::{Value, json};
    use tempfile;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_authrequest_adapter_no_client() {
        let tempdir = tempfile::tempdir().unwrap();
        let dbpath = tempdir.path().join("db");
        let shared_state = Arc::new(RwLock::new(AppState::new(FsDb::new(&dbpath).unwrap())));

        let app = adapter_app(shared_state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/preauthorize?response_type=code&client_id=foo.bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Will fail since CN not in DB
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authrequest_adapter_creates_nonce() {
        let tempdir = tempfile::tempdir().unwrap();
        let dbpath = tempdir.path().join("db");
        let shared_state = Arc::new(RwLock::new(AppState::new(FsDb::new(&dbpath).unwrap())));

        let key = CnKey::from_str("foo.bar").unwrap();
        let db = FsDb::new(&dbpath).unwrap();
        db.create_actor(&key).unwrap();
        let attrs = vec![String::from("color:red")];
        db.add_attributes(&key, &attrs).unwrap();

        let app = adapter_app(shared_state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/preauthorize?response_type=code&client_id=foo.bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let body: Value = serde_json::from_slice(&body).unwrap();
        let nonce = body["nonce"].as_str().unwrap();
        assert!(!nonce.is_empty());
    }

    #[tokio::test]
    async fn test_authenticate_adapter_bad_nonce() {
        let tempdir = tempfile::tempdir().unwrap();
        let dbpath = tempdir.path().join("db");
        let shared_state = Arc::new(RwLock::new(AppState::new(FsDb::new(&dbpath).unwrap())));

        let key = CnKey::from_str("foo.bar").unwrap();
        let db = FsDb::new(&dbpath).unwrap();
        db.create_actor(&key).unwrap();
        let attrs = vec![String::from("color:red")];
        db.add_attributes(&key, &attrs).unwrap();

        let app = adapter_app(shared_state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/authorize")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "client_id": "foo.bar",
                            "nonce": "bad_nonce",
                            "payload": "payload"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);

        response
            .headers()
            .get("Location")
            .map(|h| h.to_str().unwrap())
            .map(|l| assert!(l.contains("error=invalid_request")))
            .unwrap_or_else(|| panic!("no location header"));
    }

    #[tokio::test]
    async fn test_tokenrequest_vs_bad_code() {
        let tempdir = tempfile::tempdir().unwrap();
        let dbpath = tempdir.path().join("db");
        let shared_state = Arc::new(RwLock::new(AppState::new(FsDb::new(&dbpath).unwrap())));

        let key = CnKey::from_str("foo.bar").unwrap();
        let db = FsDb::new(&dbpath).unwrap();
        db.create_actor(&key).unwrap();
        let attrs = vec![String::from("color:red")];
        db.add_attributes(&key, &attrs).unwrap();

        let app = vs_app(shared_state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/token")
                    .header(
                        http::header::CONTENT_TYPE,
                        mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                    )
                    .body(Body::from(
                        serde_urlencoded::to_string(&TokenRequestInput {
                            grant_type: "authorization_code".to_string(),
                            code: "bad_code".to_string(),
                            client_id: "foo.bar".to_string(),
                            redirect_url: "https://auth.zpr".to_string(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_full_auth_path() {
        let tempdir = tempfile::tempdir().unwrap();
        let dbpath = tempdir.path().join("db");
        let shared_state = Arc::new(RwLock::new(AppState::new(FsDb::new(&dbpath).unwrap())));

        let key = CnKey::from_str("foo.bar").unwrap();
        let db = FsDb::new(&dbpath).unwrap();
        db.create_actor(&key).unwrap();
        let attrs = vec![String::from("color:red")];
        db.add_attributes(&key, &attrs).unwrap();

        // ======= call preauthorize to generate a nonce
        let nonce: String;
        {
            let app = adapter_app(shared_state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/preauthorize?response_type=code&client_id=foo.bar")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();

            let body: Value = serde_json::from_slice(&body).unwrap();
            nonce = String::from(body["nonce"].as_str().unwrap());
            assert!(!nonce.is_empty());
        }

        // ======= call authorize with the nonce to get an access code
        let mut code: Option<String> = None;
        {
            let app = adapter_app(shared_state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/authorize")
                        .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                        .body(Body::from(
                            serde_json::to_vec(&json!({
                                "client_id": "foo.bar",
                                "nonce": nonce.clone(),
                                "payload": "payload"
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::FOUND);

            // Now grab the code value from the location header
            response
                .headers()
                .get("Location")
                .map(|h| h.to_str().unwrap())
                .map(|l| {
                    assert!(l.contains("code="));
                    let cs = l.split("code=").nth(1).unwrap();
                    assert!(!cs.is_empty());
                    code = Some(cs.to_string());
                });
        }
        assert!(code.is_some());

        // ======= call token to get the access token
        {
            let app = vs_app(shared_state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/token")
                        .header(
                            http::header::CONTENT_TYPE,
                            mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                        )
                        .body(Body::from(
                            serde_urlencoded::to_string(&TokenRequestInput {
                                grant_type: "authorization_code".to_string(),
                                code: code.unwrap(),
                                client_id: "foo.bar".to_string(),
                                redirect_url: "https://auth.zpr".to_string(),
                            })
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let resp: AccessTokenResponse = serde_json::from_slice(&body).unwrap();

            assert!(resp.access_token.is_some());
            assert_eq!(resp.token_type, Some("bearer".to_string()));
            assert_eq!(resp.expires_in, Some(JWT_LIFETIME_SECONDS));
            assert!(resp.refresh_token.is_none());
            assert!(resp.error.is_none());

            // Now decode the JWT and check the attributes.
            let tok = resp.access_token.unwrap();
            let claims = claims_for(&tok).unwrap();
            assert_eq!(claims["aud"], "zpr");
            assert_eq!(claims["sub"], "foo.bar");
            assert_eq!(claims["iss"], "zpr/bas");
            assert_eq!(claims["z/color"], "red");
        }
    }
}
