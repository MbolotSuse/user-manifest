use std::sync::Arc;
use log::error;
use actix_web::{web, HttpResponse, Responder};
use crate::RBACController;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct HealthCheck{
    /// simple HealthCheck response, reports the number of resources in use
    num_grants: usize,
    num_permissions: usize
}

/// simple health check, reports the number of resources in use
pub async fn health(controller: web::Data<Arc<RBACController>>) -> impl Responder {
    let rbac_controller = controller.get_ref();
    let num_grants = rbac_controller.grant_controller.get_grants().len();
    let num_permissions = rbac_controller.permission_controller.get_permissions().len();
    match serde_json::to_string(&HealthCheck {
        num_grants,
        num_permissions
    }){
        Ok(output) => HttpResponse::Ok().body(output),
        Err(err) => {
            error!("error when attempting to serialize health check {:?}", err);
            HttpResponse::InternalServerError().body("internal server error, check logs for details")
        }
    }
}