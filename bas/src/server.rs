
use std::path::Path;

use tokio::net::TcpListener;

use axum::{
    body::Body,
    extract::Request,
    routing::{get, post},
    http::StatusCode,
    response::{Response, IntoResponse},
    Json,
    Router,
};

use futures_util::pin_mut;

use tower_service::Service;


use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};


use serde::{Deserialize, Serialize};

use tokio_native_tls::{
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
    TlsAcceptor,
};

use tracing::{info, warn, error};


#[derive(Debug, Serialize)]
pub struct AdapterAuthRequest {
    pub nonce: String, // base64 encoded bytes
}

#[derive(Debug, Deserialize)]
pub struct AdapterAuthentication {
    pub state: String,
    pub nonce: String, // copied from response to adapter
    pub payload: String, // base64 encoded signature payload created by adapter
}


#[derive(Debug, Serialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String, // "bearer"
    pub expires_in: u64, // seconds
    pub refresh_token: String,
    pub zpr_attrs: Vec<String>, // attributes from our database
}



pub async fn start_server(key_file: &Path, cert_file: &Path) {
    tokio::spawn(start_vs_server(native_tls_acceptor(key_file, cert_file), 3999));
    start_adapter_server(native_tls_acceptor(key_file, cert_file), 4000).await;
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



async fn start_adapter_server(acceptor: NativeTlsAcceptor, port: u16) {

    let app = Router::new()
        .route("/authrequest", post(authrequest_adapter))
        .route("/authenticate", post(authenticate_adapter));

    start_tls_server("adapter services", app, acceptor, port).await;
}


async fn start_vs_server(acceptor: NativeTlsAcceptor, port: u16) {
    let app = Router::new()
        .route("/tokenrequest", post(tokenrequest_vs));
        // TODO: /refresh

    start_tls_server("visa service services", app, acceptor, port).await;
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



// This an OAuth style API used by the visa service to obtain an access token
// given an authorization code.
//
// Requires query params:
// - grant_type (must be set to "authorization_code")
// - code (the code returned from adapter authentication)
// - client_id
// - redirect_url (should be set to "https://auth.zpr")
//
// We return a JSON object.
async fn tokenrequest_vs(_req: Request) -> (StatusCode, Json<AccessTokenResponse>) {
    let tok = AccessTokenResponse{
        access_token: "not valid".to_string(),
        token_type: "bearer".to_string(),
        expires_in: 3600,
        refresh_token: "not valid".to_string(),
        zpr_attrs: vec![],
    };
    return(StatusCode::OK, Json(tok));
}



// This is the OAuth style API used by an adapter to authentiate its actor with
// this authentication service.  This ends up returning a challenge to the
// adapter which it will sign and return in a call to `authenticate_adapter`.
//
// This expects form encoded params:
// - response_type (must be set to "code")
// - client_id
// - scope
// - state (ignored)
//
// Redirect URL (part of OAuth) is not checked and whenever it is used
// it must be set to "https://auth.zpr"
//
// This will create a nonce for this client to use for generating as [AdapterAuthentication].
// We will keep track of the client_id/nonce used.
async fn authrequest_adapter(_req: Request) -> (StatusCode, Json<AdapterAuthRequest>) {
    return(StatusCode::OK, Json(AdapterAuthRequest {
        nonce: "nonce".to_string()
    }));
}


// This is the OAuth style API used by an adapter to authenticate its actor with
// this authentication service.  This accepts the signature payload from the adapter
// and we will check that it is valid against a public key in our database.
//
// This expects a JSON post data.
//
// We need to check the signature and then return a redirect with
// OAuth style query params:
// - code
// - state (copied from request)
//
// Not yet sure if we create the BLOB here or let adapter do it.
async fn authenticate_adapter(Json(_payload): Json<AdapterAuthentication>) -> Result<Response, StatusCode> {

    // TODO: If state is set we are to return it even if this is an error.

    let location = format!("https://auth.zpr?error=unsupported_response_type&error_description=not+implemented"); // TODO

    let resp = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap();
    Ok(resp)
}