use std::sync::{Arc, RwLock};
use log::error;
use actix_web::{web, HttpResponse, Responder};
use crate::RBACController;

/// health check function. Not intended to take any parameters
pub async fn health(controller: web::Data<Arc<RwLock<RBACController>>>) -> impl Responder{
    let rbac_controller = controller.into_inner();
    let read_result = rbac_controller.read();
    match read_result{
        Ok(_res) => {
            HttpResponse::Ok().body("ok")
        },
        Err(err) => {
            error!("Unable to read from controller with error {:?}", err);
            HttpResponse::InternalServerError().body("internal server error")
        }
    }
}