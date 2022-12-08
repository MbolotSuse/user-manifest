use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use actix_web::{web, HttpResponse, Responder};
use log::error;
use crate::RBACController;
use crate::endpoints::structs::{GrantInput, Filter, grant_filter_applies};
use crate::controller::rbac_grant::RBACGrant;
use k8s_openapi::api::rbac::v1::PolicyRule;
use std::error::Error;

pub async fn get_permissions(input: web::Json<GrantInput>, controller: web::Data<Arc<RwLock<RBACController>>>) -> impl Responder{
    let grant_input = input.into_inner();
    let grant_subject = grant_input.clone().to_grant_subject();
    let rbac_controller = controller.into_inner();
    let read_result = rbac_controller.read();
    match read_result{
        Ok(result) => {
            let grants_option = result.user_to_grant.get(&grant_subject);
            match grants_option{
                Some(grants) => {
                    let convert_option = create_permission_output(grants, grant_input.filter, &result);
                    match convert_option{
                        Ok(convert_option) => HttpResponse::Ok().body(convert_option),
                        Err(err) => {
                            error!("Unable to convert to a json with error {}", err);
                            HttpResponse::InternalServerError().body("internal server error")
                        },
                    }
                },
                None => {
                    return HttpResponse::NotFound().body("no grants for that subject");
                }
            }
        },
        Err(err) => {
            error!("Unable to read from controller with error {:?}", err);
            HttpResponse::InternalServerError().body("internal server error")
        }
    }
}

fn create_permission_output(grants: &HashSet<RBACGrant>, filter: Option<Filter>, controller: &RwLockReadGuard<RBACController>) -> Result<String, Box<dyn Error>>{
    let mut output_map:HashMap<String, Vec<PolicyRule>> = HashMap::new();
    let filter_valid = filter.is_some();
    for grant in grants{
        if filter_valid{
            // safe to call unwrap since we confirmed it is some before calling
            if !grant_filter_applies(&grant, &filter.as_ref().unwrap()){
                continue;
            }
        }
        let namespace_key = match grant.clone().namespace{
            Some(ns) => ns,
            None => "".to_string(),
        };
        let output_rules = match controller.grant_to_permissions.get(&grant.permissions_id){
            Some(rules) => rules,
            None => {
                return match &grant.permissions_id.namespace {
                    Some(ns) => Result::Err(format!("missing rules entry for {} in {}", grant.permissions_id.name, ns).into()),
                    None => Result::Err(format!("missing rules entry for {}", grant.permissions_id.name).into()),
                }
            }
        };
        let entry = output_map.entry(namespace_key).or_insert(Vec::new());
        entry.append(&mut output_rules.clone());
    }
    let convert_result = serde_json::to_string(&output_map);
    return match convert_result {
        Ok(result) => Result::Ok(result),
        Err(err) => Result::Err(format!("Unable to convert to json with error {}", err).into()),
    }
}