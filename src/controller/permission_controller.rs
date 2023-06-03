use crate::controller::rbac_grant::{RBACId, IDType};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, ClusterRole};
use kube::{api::{Api, ListParams}, runtime::watcher, Client};
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

    fn remove_all_of_type(&self, id_type: IDType){
        // as outlined in the mini-redis, necessary to acquire lock/access state
        let mut state =  self.state.lock().unwrap();
        let state = &mut *state;
        // keep only the entries which do not have the specified id type (or remove all that are
        // of the specified id type)
        state.id_to_permissions.retain(|k, _| k.rbac_type != id_type);
    }
}

async fn refresh_roles(client: Client, shared: Arc<Shared>){
    info!("Starting role controller");
    let role_api = Api::<Role>::all(client.clone());
    let role_watcher = watcher(role_api, ListParams::default());
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await{
       match event{
           Event::Applied(role) => {
               let rbac_id = RBACId::from_role(&role);
               // remove the current permission and store the new ones in case our permissions changed
               shared.remove_permission_id(&rbac_id);
               shared.store_permission_id(&rbac_id, &role.rules.unwrap_or_default());
           },
           Event::Restarted(roles) => {
               // watch restarted, remove all current records and refill with new ones
               shared.remove_all_of_type(IDType::Role);
               for role in roles{
                   let rbac_id = RBACId::from_role(&role);
                   shared.store_permission_id(&rbac_id, &role.rules.unwrap_or_default());
               }
           },
           Event::Deleted(role) => {
               // remove our current record of this role since it's now deleted
               let rbac_id = RBACId::from_role(&role);
               shared.remove_permission_id(&rbac_id);
           },
       }
    }
}

async fn refresh_cluster_role(client: Client, shared: Arc<Shared>){
    info!("Starting cluster role controller");
    let cluster_role_api = Api::<ClusterRole>::all(client.clone());
    let cluster_role_watcher = watcher(cluster_role_api, ListParams::default());
    pin_mut!(cluster_role_watcher);
    while let Ok(Some(event)) = cluster_role_watcher.try_next().await{
       match event{
           Event::Applied(cluster_role) => {
               let rbac_id = RBACId::from_cluster_role(&cluster_role);
               // remove stale permission and re-add
               shared.remove_permission_id(&rbac_id);
               shared.store_permission_id(&rbac_id, &cluster_role.rules.unwrap_or_default())
           },
           Event::Restarted(cluster_roles) => {
               // watch restarted, purge current events and refill
               shared.remove_all_of_type(IDType::ClusterRole);
               for cluster_role in cluster_roles{
                   let rbac_id = RBACId::from_cluster_role(&cluster_role);
                   shared.store_permission_id(&rbac_id, &cluster_role.rules.unwrap_or_default());
               }
           },
           Event::Deleted(cluster_role) => {
               // remove our current record since this permission is deleted
               let rbac_id = RBACId::from_cluster_role(&cluster_role);
               shared.remove_permission_id(&rbac_id);
           },
       }
    }
}
