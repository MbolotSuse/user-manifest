mod controller;
mod endpoints;

use std::sync::{Arc};
use std::env;
use std::error::Error;
use actix_web::{web, App, HttpServer};
use endpoints::grants::get_all_grants;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use kube::Client;
use env_logger;
use log::info;
use crate::controller::grant_controller::GrantController;
use crate::controller::permission_controller::PermissionController;
use crate::controller::rbac_controller::RBACController;
use crate::endpoints::health::health;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let client_result = Client::try_default().await;
    let client = match client_result{
        Ok(new_client) => new_client,
        Err(result) => return Err(std::io::Error::new(std::io::ErrorKind::Other,result.to_string())),
    };
    let grant_controller = GrantController::new(client.clone());
    let permission_controller = PermissionController::new(client.clone());
    let rbac_controller = Arc::new(RBACController{
        grant_controller,
        permission_controller,
    });
    let server = HttpServer::new( move || {
        App::new().
            app_data(web::Data::new(Arc::clone(&rbac_controller))).
            route("/health", web::get().to(health)).
            route("/grants", web::get().to(get_all_grants))
    });
    match get_ssl_builder(){
        Ok(builder) => {
            info!("Using openssl");
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
