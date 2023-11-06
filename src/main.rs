mod controller;
mod endpoints;

use crate::controller::grant_controller::GrantController;
use crate::controller::permission_controller::PermissionController;
use crate::controller::rbac_controller::RBACController;
use crate::endpoints::health::health;
use actix_web::{web, App, HttpServer};
use endpoints::grants::get_all_grants;
use env_logger;
use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use kube::Client;
use log::info;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::env;
use std::error::Error;
use std::sync::Arc;
use std::{fs::File, io::BufReader};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let client_result = Client::try_default().await;
    let client = match client_result {
        Ok(new_client) => new_client,
        Err(result) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                result.to_string(),
            ))
        }
    };
    let grant_controller = GrantController::new(client.clone());
    let permission_controller = PermissionController::new(client.clone());
    let rbac_controller = Arc::new(RBACController {
        grant_controller,
        permission_controller,
    });
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Arc::clone(&rbac_controller)))
            .route("/health", web::get().to(health))
            .route("/grants", web::get().to(get_all_grants))
    });
    match get_ssl_config() {
        Ok(config) => {
            info!("Using openssl");
            server.bind_rustls("127.0.0.1:8080", config)?.run().await
        }
        Err(err) => {
            info!(
                "Unable to configure ssl with err {}, will run without ssl",
                err
            );
            server.bind(("127.0.0.1", 8080))?.run().await
        }
    }
}

fn get_ssl_config() -> Result<ServerConfig, Box<dyn Error>> {
    // adapted from https://github.com/actix/examples/blob/ce10427457ea187b9c189367d136e7504fef0c2d/https-tls/rustls/src/main.rs#L44
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // try to read the location of the certs from the TLS_CERT_DIR directory
    let dir_path = env::var("TLS_CERT_DIR")?;
    let key_path: String;
    let cert_path: String;
    if dir_path.ends_with("/") {
        // only need to transfer ownership of one value since we don't use dir_path after this method
        key_path = dir_path.clone() + "key.pem";
        cert_path = dir_path + "cert.pem";
    } else {
        key_path = dir_path.clone() + "/key.pem";
        cert_path = dir_path + "/cert.pem";
    };

    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let cert_reader = &mut BufReader::new(cert_file);
    let key_reader = &mut BufReader::new(key_file);
    let cert_chain: Vec<Certificate> = certs(cert_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_reader)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    let config = config.with_single_cert(cert_chain, keys.remove(0))?;
    return Ok(config);
}
