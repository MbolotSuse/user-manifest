mod controller;
mod endpoints;

use std::sync::{Arc, RwLock};
use std::env;
use std::error::Error;
use actix_web::{web, App, HttpServer, rt};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use kube::Client;
use env_logger;
use log::info;
use crate::controller::rbac_controller::{RBACController, run_controllers};
use crate::endpoints::health::health;
use crate::endpoints::grants::{get_grants, get_grant_counts};
use crate::endpoints::permissions::get_permissions;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let client_result = Client::try_default().await;
    let controller = crate::controller::rbac_controller::new();
    let rbac_controller = Arc::new(RwLock::new(controller));
    let client = match client_result{
        Ok(new_client) => new_client,
        Err(result) => return std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::Other,result.to_string())),
    };
    let thread_controller = Arc::clone(&rbac_controller);
    // rbac_controllers need to run in the background to refresh memberships will server runs
    rt::spawn(run_controllers(client, thread_controller));
    let server = HttpServer::new( move || {
        App::new().
            app_data(web::Data::new(Arc::clone(&rbac_controller))).
            route("/health", web::get().to(health)).
            route("/grants/subject", web::post().to(get_grants)).
            route("/grants/count", web::get().to(get_grant_counts)).
            route("/permissions/subject", web::post().to(get_permissions))
    });
    match get_ssl_builder(){
        Ok(builder) => {
            server.bind_openssl("127.0.0.1:8080", builder)?
                .run()
                .await
        },
        Err(err) => {
            info!("Unable to configure ssl with err {}, will run without ssl", err);
            server.bind(("127.0.0.1", 8080))?
                .run()
                .await
        }
    }
}

/// Mostly an error handling function which attempts to find key.pem and cert.pem in the directory
/// Specified by TLS_CERT_DIR and load them into a format usable by the server
fn get_ssl_builder() -> Result<SslAcceptorBuilder, Box<dyn Error>>{
    let dir_path = match env::var("TLS_CERT_DIR"){
        Ok(path) => path,
        Err(err) => return Result::Err(format!("Unable to read env variable TLS_CERT_DIR with err {}", err).into()),
    };
    let key_path: String;
    let cert_path: String;
    if dir_path.ends_with("/"){
        // only need to transfer ownership of one value since we don't use dir_path after this method
        key_path = dir_path.clone() + "key.pem";
        cert_path = dir_path + "cert.pem";
    }else{
        key_path = dir_path.clone() + "/key.pem";
        cert_path = dir_path + "/cert.pem";
    };
    let mut builder = match SslAcceptor::mozilla_intermediate(SslMethod::tls()){
        Ok(acceptor) => acceptor,
        Err(err) => return Result::Err(format!("Unable to init ssl acceptor with error {}", err).into()),
    };
    match builder.set_private_key_file(key_path, SslFiletype::PEM){
        Ok(_res) => (),
        Err(err) => return Result::Err(format!("Unable to add private key with error {}", err).into()),
    };
    match builder.set_certificate_chain_file(cert_path){
        Ok(_res) => (),
        Err(err) => return Result::Err(format!("Unable to add certificate with error {}", err).into()),
    };
    return Result::Ok(builder);
}