use crate::controller::rbac_grant::{RBACId};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, ClusterRole};
use kube::{api::{Api, ListParams}, runtime::{watcher, WatchStreamExt}, Client};
use log::info;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use actix_web::rt;
use futures::{pin_mut, TryStreamExt};
use kube::runtime::watcher::Event;

// structure heavily influenced by https://github.com/tokio-rs/mini-redis/blob/master/src/db.rs
// TODO: Reduce/remove the use of .unwrap()
#[derive(Debug, Clone)]
pub struct PermissionController {
    /// Handles the shared state
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    /// Shared state guarded by a mutex
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    id_to_permissions: HashMap<RBACId, Vec<PolicyRule>>
}

impl PermissionController {
    pub(crate) fn new(client: Client) -> PermissionController {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                id_to_permissions: HashMap::new(),
            })
        });

        rt::spawn(refresh_roles(client.clone(), shared.clone()));
        rt::spawn(refresh_cluster_role(client.clone(), shared.clone()));

        PermissionController{shared}
    }
    pub(crate) fn get_permission_for_id(&self, id: &RBACId) -> Option<Vec<PolicyRule>>{
        let mut state = self.shared.state.lock().unwrap();
        let state = &mut *state;
        match state.id_to_permissions.get(id){
            Some(permissions) => Some(permissions.clone()),
            None => None,
        }
    }

    pub(crate) fn get_permissions(&self) -> HashMap<RBACId, Vec<PolicyRule>>{
        let mut state = self.shared.state.lock().unwrap();
        let state = &mut *state;
        state.id_to_permissions.clone()
    }
}

impl Shared {
    fn remove_permission_id(&self, id: &RBACId){
        // as outlined in the mini-redis, necessary to acquire lock/access state
        let mut state =  self.state.lock().unwrap();
        let state = &mut *state;
        state.id_to_permissions.remove(id);
    }

    fn store_permission_id(&self, id: &RBACId, rules: &Vec<PolicyRule>){
        // as outlined in the mini-redis, necessary to acquire lock/access state
        let mut state =  self.state.lock().unwrap();
        let state = &mut *state;
        state.id_to_permissions.insert(id.clone(), rules.clone());
    }
}

async fn refresh_roles(client: Client, shared: Arc<Shared>){
    info!("Starting role controller");
    let role_api = Api::<Role>::all(client.clone());
    let twatcher = watcher(role_api, ListParams::default());
    pin_mut!(twatcher);
    while let Ok(Some(event)) = twatcher.try_next().await{
       match event{
           Event::Deleted(deleted_role) => {},
           Event::Applied(changed_role) => {},
           Event::Restarted(roles) => {},
       }
    }
    let role_watcher = watcher(role_api, ListParams::default()).touched_objects();
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await{
        let rbac_id = RBACId::from_role(&event);
        // remove the current record so we can update the permissions
        shared.remove_permission_id(&rbac_id);
        // don't update permissions if we are for a deleting role or a role without rules
        if event.metadata.deletion_timestamp.is_none() && event.rules.is_some(){
            shared.store_permission_id(&rbac_id, &event.rules.unwrap());
        }
    }
}

async fn refresh_cluster_role(client: Client, shared: Arc<Shared>){
    info!("Starting cluster role controller");
    let role_api = Api::<ClusterRole>::all(client.clone());
    let role_watcher = watcher(role_api, ListParams::default()).touched_objects();
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await {
        let rbac_id = RBACId::from_cluster_role(&event);
        // remove the current record so we can update the permissions
        shared.remove_permission_id(&rbac_id);
        // don't update permissions if we are for a deleting role or a role without rules
        if event.metadata.deletion_timestamp.is_none() && event.rules.is_some(){
            shared.store_permission_id(&rbac_id, &event.rules.unwrap());
        }
    }
}