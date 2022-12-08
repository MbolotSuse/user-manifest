use futures::{pin_mut, TryStreamExt};
use std::collections::{HashMap, HashSet};
use kube::{api::{Api, ListParams}, runtime::{watcher, WatchStreamExt}, Client};
use crate::controller::rbac_grant::{RBACGrant, RBACId, GrantSubject, convert_role_binding_to_grant, convert_cluster_role_binding_to_grant, convert_to_grant_subject, get_rules};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, ClusterRole, RoleBinding, ClusterRoleBinding, Subject};
use log::{info, error};
use std::error::Error;
use std::sync::{Arc, RwLock};
use actix_web::rt;

pub struct RBACController{
    pub(crate) user_to_grant: HashMap<GrantSubject, HashSet<RBACGrant>>,
    pub(crate) grant_to_permissions: HashMap<RBACId, Vec<PolicyRule>>
}

pub fn new() -> RBACController{
    let default_user_grant: HashMap<GrantSubject, HashSet<RBACGrant>> = HashMap::new();
    let default_grant_to_perms: HashMap<RBACId, Vec<PolicyRule>> = HashMap::new();
    return RBACController{
        user_to_grant: default_user_grant,
        grant_to_permissions: default_grant_to_perms
    }
}

pub async fn run_controllers(client: Client, controller: Arc<RwLock<RBACController>>){
    info!("Starting controllers");
    rt::spawn(run_role_binding_controller(client.clone(), Arc::clone(&controller)));
    rt::spawn(run_cluster_role_binding_controller(client.clone(), Arc::clone(&controller)));
}

async fn run_role_binding_controller(client: Client, controller: Arc<RwLock<RBACController>>){
    let role_binding_api = Api::<RoleBinding>::all(client.clone());
    let role_watcher = watcher(role_binding_api, ListParams::default()).applied_objects();
    info!("Starting role_binding controller");
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await {
        let subjects: Vec<Subject> = match event.clone().subjects{
            Some(event_subjects) => event_subjects,
            // if the event has no subjects than no permissions have been given, so we don't need to store anything
            None => continue,
        };
        let grant_result = convert_role_binding_to_grant(&event);
        let grant = match grant_result{
            Ok(result) => result,
            Err(result) => {
                error!("Unable to convert role_binding {:?} to RBACGrant with error {:?}, will skip", event, result);
                continue;
            },
        };
        let store_result = store_grant(grant, subjects,Arc::clone(&controller), client.clone()).await;
        match store_result{
            Ok(result) => {
                if !result{
                    // this should never happen, but handle it just in case
                    error!("Did not store grant for event {:?}", event);
                }
            },
            Err(err) => {
                error!("Failed to store grant for event {:?}, with error {:?}", event, err)
            }
        }
    }
}

async fn run_cluster_role_binding_controller(client: Client, controller: Arc<RwLock<RBACController>>){
    let cluster_role_binding_api = Api::<ClusterRoleBinding>::all(client.clone());
    let cluster_role_watcher = watcher(cluster_role_binding_api, ListParams::default()).applied_objects();
    info!("Starting cluster_role_binding controller");
    pin_mut!(cluster_role_watcher);
    while let Ok(Some(event)) = cluster_role_watcher.try_next().await {
        let subjects: Vec<Subject> = match event.clone().subjects{
            Some(event_subjects) => event_subjects,
            // if the event has no subjects than no permissions have been given, so we don't need to store anything
            None => continue,
        };
        let grant_result = convert_cluster_role_binding_to_grant(&event);
        let grant = match grant_result{
            Ok(result) => result,
            Err(result) => {
                error!("Unable to convert cluster_role_binding {:?} to RBACGrant with error {:?}, will skip", event, result);
                continue;
            },
        };
        let store_result = store_grant(grant, subjects,Arc::clone(&controller), client.clone()).await;
        match store_result{
            Ok(result) => {
                if !result{
                    // this should never happen, but handle it just in case
                    error!("Did not store grant for event {:?}", event);
                }
            },
            Err(err) => {
                error!("Failed to store grant for event {:?}, with error {:?}", event, err)
            }
        }
    }
}

async fn store_grant(grant:RBACGrant, subjects: Vec<Subject>, controller: Arc<RwLock<RBACController>>, client: Client) -> Result<bool, Box<dyn Error>>{
    let role_ns = match grant.clone().permissions_id.namespace{
        Some(ns) => ns,
        None => "".to_string(),
    };
    let ns_role_api = Api::<Role>::namespaced(client.clone(), role_ns.as_str());
    let cluster_role_api = Api::<ClusterRole>::all(client.clone());
    let rules_result = get_rules(&grant, ns_role_api, cluster_role_api.clone()).await;
    match rules_result{
        Ok(rules) => {
            let write_result = controller.write();
            match write_result{
                Ok(mut result) => {
                    if !result.grant_to_permissions.contains_key(&grant.permissions_id) {
                        result.grant_to_permissions.insert(grant.permissions_id.clone(), rules);
                    }
                },
                Err(result) => {
                    return Result::Err(format!("Unable to acquire rw lock with error: {:?}", result).into());
                },
            }
            for subject in subjects{
                let controller = controller.clone();
                let write_result = controller.write();
                match write_result {
                    Ok(mut result) => {
                        let grant_subject_result = convert_to_grant_subject(subject);
                        match grant_subject_result{
                            Ok(grant_subject) => {
                                let entry = result.user_to_grant.entry(grant_subject).or_insert(HashSet::new());
                                if !entry.contains(&grant){
                                    // Can safely ignore the return - we don't care if the grant was updated
                                    entry.insert(grant.clone());
                                }
                            },
                            Err(err) => return Result::Err(format!("unable to convert to grant subject {}", err).into()),
                        }
                    },
                    Err(result) => {
                        return Result::Err(format!("Unable to acquire rw lock with error: {:?}", result).into());
                    }
                }
            }
            Result::Ok(true)
        },
        Err(err) => {
            Result::Err(format!("Unable to get rules for grant {} with error: {}, skipping", grant.name, err).into())
        }
    }
}