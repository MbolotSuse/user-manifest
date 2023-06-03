use futures::{TryStreamExt, pin_mut};
use std::collections::{HashMap, HashSet};
use kube::{api::{Api, ListParams}, runtime::{watcher, WatchStreamExt}, Client};
use crate::controller::rbac_grant::{RBACGrant, GrantSubject};
use k8s_openapi::api::rbac::v1::{RoleBinding, ClusterRoleBinding};
use log::info;
use std::sync::{Arc, Mutex};
use actix_web::rt;

// structure heavily influenced by https://github.com/tokio-rs/mini-redis/blob/master/src/db.rs
// TODO: Reduce/remove the use of .unwrap()
#[derive(Debug, Clone)]
pub struct GrantController {
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
    user_to_grant: HashMap<GrantSubject, HashSet<RBACGrant>>,
    grant_to_user: HashMap<RBACGrant, HashSet<GrantSubject>>,
}

impl GrantController {
    pub(crate) fn new(client: Client) -> GrantController{
        let shared = Arc::new(Shared {
            state: Mutex::new(State{
                user_to_grant: HashMap::new(),
                grant_to_user: HashMap::new()
            })
        });

        rt::spawn(refresh_role_bindings(client.clone(), shared.clone()));
        rt::spawn(refresh_cluster_role_bindings(client.clone(), shared.clone()));

        GrantController{shared}
    }
    pub(crate) fn get_grants_for_subject(&self, subject: &GrantSubject) -> Option<HashSet<RBACGrant>>{
        let mut state = self.shared.state.lock().unwrap();
        let state = &mut *state;
        match state.user_to_grant.get(subject){
            Some(grants) => Some(grants.clone()),
            None => None,
        }
    }
    
    pub(crate) fn get_grants(&self) -> HashMap<GrantSubject, HashSet<RBACGrant>> {
        let mut state = self.shared.state.lock().unwrap();
        let state = &mut *state;
        state.user_to_grant.clone()
    }
}

impl Shared {
    fn remove_grant_for_subject(&self, subject: &GrantSubject, grant: &RBACGrant){
        // as outlined in the mini-redis, necessary to acquire lock/access state
        let mut state =  self.state.lock().unwrap();
        let state = &mut *state;
        match state.user_to_grant.get_mut(subject){
            Some(grants) => grants.remove(grant),
            // no need to remove grants if we don't have any for this user
            // hack to make the match arms match return type
            None => false,
        };
        match state.grant_to_user.get_mut(grant){
            Some(users) => users.remove(subject),
            // hack to make the match arms match return type
            None => false,
        };
    }

    fn add_grant_for_subject(&self, subject: &GrantSubject, grant: &RBACGrant){
        // as outlined in the mini-redis, necessary to acquire lock/access state
        let mut state =  self.state.lock().unwrap();
        let state = &mut *state;
        // provide defaults for grants/users in case we don't have a record for this user yet
        let current_grants = state.user_to_grant.entry(subject.clone()).or_insert(HashSet::new());
        current_grants.insert(grant.clone());

        let current_users = state.grant_to_user.entry(grant.clone()).or_insert(HashSet::new());
        current_users.insert(subject.clone());
    }

    fn get_current_subjects_for_grant(&self, grant: &RBACGrant) -> Option<HashSet<GrantSubject>>{
        let mut state = self.state.lock().unwrap();
        let state = &mut *state;
        match state.grant_to_user.get(grant){
            Some(subjects) => Some(subjects.clone()),
            None => None,
        }
    }

    fn remove_grant(&self, grant: &RBACGrant){
        let mut state = self.state.lock().unwrap();
        let state = &mut *state;
        let default: HashSet<GrantSubject> = HashSet::new();
        let subjects = match state.grant_to_user.get(grant){
            Some(subs) => subs,
            None => &default,
        };
    }
}

async fn refresh_role_bindings(client: Client, shared: Arc<Shared>){
    info!("Starting role binding controller");
    let role_binding_api = Api::<RoleBinding>::all(client.clone());
    let role_watcher = watcher(role_binding_api, ListParams::default()).touched_objects();
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await {
        let subjects = event.clone().subjects.unwrap_or_default();
        let grant = RBACGrant::from_role_binding(&event);
        let previous_subjects = match shared.get_current_subjects_for_grant(&grant){
            Some(subs) => subs,
            None => HashSet::new()
        };
        // remove all grants previously registered
        for previous_subject in previous_subjects{
           shared.remove_grant_for_subject(&previous_subject, &grant);
        }
        // if we aren't in a deletion state, re-add all new grants
        if event.metadata.deletion_timestamp.is_none(){
            for subject in subjects{
                let grant_subject = GrantSubject::from_subject(&subject);
                shared.add_grant_for_subject(&grant_subject, &grant);
            };
        }
    }
}

async fn refresh_cluster_role_bindings(client: Client, shared: Arc<Shared>){
    info!("Starting cluster role binding controller");
    let role_binding_api = Api::<ClusterRoleBinding>::all(client.clone());
    let role_watcher = watcher(role_binding_api, ListParams::default()).touched_objects();
    pin_mut!(role_watcher);
    while let Ok(Some(event)) = role_watcher.try_next().await {
        let subjects = event.clone().subjects.unwrap_or_default();
        let grant_result = RBACGrant::from_cluster_role_binding(&event);
        // remove all grants previously registered
        let previous_subjects = match shared.get_current_subjects_for_grant(&grant_result){
            Some(subs) => subs,
            None => HashSet::new()
        };
        for previous_subject in previous_subjects{
            shared.remove_grant_for_subject(&previous_subject, &grant_result);
        }
        // if we aren't in a deletion state, re-add all new grants
        if event.metadata.deletion_timestamp.is_none(){
            for subject in subjects{
                let grant_subject = GrantSubject::from_subject(&subject);
                shared.add_grant_for_subject(&grant_subject, &grant_result);
            };
        }
    }
}
