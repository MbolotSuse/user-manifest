use std::sync::Arc;
use log::error;
use actix_web::{web, HttpResponse, Responder};
use crate::RBACController;
use serde::Serialize;

use crate::endpoints::output_types::{OutputGrant, OutputSubject};


#[derive(Serialize, Clone)]
pub struct OutputAll {
    pub subject_grants: Vec<OutputSubjectGrant>
}

#[derive(Serialize, Clone)]
pub struct OutputSubjectGrant {
    pub subject: OutputSubject,
    pub grants: Vec<OutputGrant>,
}

/// simple health check, reports the number of resources in use
pub async fn get_all_grants(controller: web::Data<Arc<RBACController>>) -> impl Responder {
    let rbac_controller = controller.get_ref();
    let grants = rbac_controller.grant_controller.get_grants();
    let mut output_subject_grants: Vec<OutputSubjectGrant> = Vec::new(); 
    for (subject, grants) in grants{
        let output_subject = OutputSubject::from_grant_subject(subject);
        let mut output_grants: Vec<OutputGrant> = Vec::new();
        for grant in grants{
            let output_grant = OutputGrant::from_rbac_grant(grant);
            output_grants.push(output_grant);
        }
        output_subject_grants.push(OutputSubjectGrant{
            subject: output_subject,
            grants: output_grants,
        })
    }
    match serde_json::to_string(&OutputAll {
        subject_grants: output_subject_grants,
    }){
        Ok(output) => HttpResponse::Ok().body(output),
        Err(err) => {
            error!("error when attempting to serialize health check {:?}", err);
            HttpResponse::InternalServerError().body("internal server error, check logs for details")
        }
    }
}
