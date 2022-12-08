use std::fmt;
use std::fmt::{Formatter};
use std::hash::Hash;
use std::error::Error;
use kube::api::Api;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, ClusterRole, RoleBinding, ClusterRoleBinding, Subject};

/// Generic form of an identifier for an RBAC resource (role/cluster role). Does not contain rules
/// To avoid re-storing rules in memory
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct RBACId{
    /// type of resource which holds permissions - e.x. role or cluster_role
    pub(crate) rbac_type: IDType,
    /// namespace which this RBAC resource lives in - may be none if source resource is cluster-wide
    pub(crate) namespace: Option<String>,
    /// name of the rbac resource
    pub(crate) name: String,
}

/// Object which grants RBAC permissions. Generic form of role_binding/cluster_role_binding
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct RBACGrant {
    //TODO: Custom hash (and maybe eq?) function which ignores permissions_id.
    /// type of resource which grants RBAC permissions - e.x. role_binding or cluster_role_binding
    pub(crate) grant_type: GrantType,
    /// namespace which the permission grant occurs in - may be none if the grant is cluster-wide
    pub(crate) namespace: Option<String>,
    /// name of the grant - unique within the grant_type for this namespace
    pub(crate) name: String,
    /// the id of the permissions granted by this permissions grant
    pub(crate) permissions_id: RBACId,
}

/// Enum for the Types of Grants - Can be expanded to support other sources of permissions
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum GrantType{
    RoleBinding,
    ClusterRoleBinding,
}

impl fmt::Display for GrantType{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self{
            GrantType::RoleBinding => {
                write!(f, "RoleBinding")
            }
            GrantType::ClusterRoleBinding => {
                write!(f, "ClusterRoleBinding")
            },
        }
    }
}

/// Enum for the Type of RBAC resources - Can be expanded to other resources which hold RBAC rules
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum IDType{
    Role,
    ClusterRole,
}

impl fmt::Display for IDType{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self{
            IDType::Role => {
                write!(f, "Role")
            }
            IDType::ClusterRole => {
                write!(f, "ClusterRole")
            },
        }
    }
}

/// User/ServiceAccount/Group that a binding applies to. Re-implemented form of a k8s subject so that we
/// can hash it for use in our maps
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct GrantSubject{
    /// kind of the subject - User/Group/ServiceAccount
    pub kind: SubjectKind,
    /// name of the subject, unique within kind/namespace
    pub name: String,
    /// the namespace the subject is in. None in cases of users/groups, Some in cases of ServiceAccounts
    pub namespace: Option<String>,
    /// taken directly from the k8s subject - api group this kind belongs to
    pub api_group: String,
}

/// Enum for the ptotential kinds of subjects
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum SubjectKind{
    User,
    Group,
    ServiceAccount,
}

impl fmt::Display for SubjectKind{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self{
            SubjectKind::User => {
                write!(f, "User")
            }
            SubjectKind::Group => {
                write!(f, "Group")
            },
            SubjectKind::ServiceAccount => {
                write!(f, "ServiceAccount")
            }
        }
    }
}

pub(crate) async fn get_rules(grant: &RBACGrant, role_api: Api::<Role>, cluster_role_api: Api::<ClusterRole>) -> Result<Vec<PolicyRule>, Box<dyn Error>>{
    if grant.permissions_id.rbac_type == IDType::Role {
        let role_result = role_api.get(grant.permissions_id.name.as_str()).await;
        match role_result{
            Ok(role_result) => {
                match role_result.rules {
                    Some(role_rules) => Result::Ok(role_rules),
                    None => Result::Ok(Vec::new()),
                }
            },
            Err(role_result) => {
                return Result::Err(format!("Unable to retrieve details for role {} due to error {:?}", grant.permissions_id.name, role_result).into());
            }
        }
    }else if grant.permissions_id.rbac_type == IDType::ClusterRole {
        let cluster_role_result = cluster_role_api.get(grant.permissions_id.name.as_str()).await;
        // TODO: Technically, these are identical. However, the return type on cluster_role_api and role_api's get methods are different
        // This could probably be solved with a macro
        match cluster_role_result {
            Ok(role_result) => {
                match role_result.rules {
                    Some(role_rules) => Result::Ok(role_rules),
                    None => Result::Ok(Vec::new()),
                }
            },
            Err(role_result) => {
                return Result::Err(format!("Unable to retrieve details for role {} due to error {:?}", grant.permissions_id.name, role_result).into());
            }
        }
    }else{
        return Result::Err(format!("Invalid rbac type {} on grant {}", grant.permissions_id.rbac_type, grant.name).into())
    }
}

pub(crate) fn convert_role_binding_to_grant(role_binding: &RoleBinding) -> Result<RBACGrant, Box<dyn Error>>{
    let binding_name = match role_binding.metadata.name.clone(){
        Some(name) => name,
        None => return Result::Err("role binding was missing name".into())
    };
    let binding_namespace = match role_binding.metadata.namespace.clone(){
        Some(namespace) => namespace,
        None => return Result::Err("role binding namespace was missing".into())
    };
    let rbac_type;
    let mut id_namespace: Option<String> = None;
    match role_binding.role_ref.kind.as_str(){
        "Role" => {
            rbac_type = IDType::Role;
            id_namespace = Some(binding_namespace.clone());
        },
        "ClusterRole" => {
            rbac_type = IDType::ClusterRole;
        },
        _ =>{
            return Result::Err(format!("role ref was for a {}, not a ClusterRole or Role", role_binding.role_ref.kind).into())
        }
    };

    Result::Ok(RBACGrant{
        grant_type: GrantType::RoleBinding,
        namespace: Some(binding_namespace),
        name: binding_name,
        permissions_id: RBACId{
            rbac_type,
            namespace: id_namespace,
            name: role_binding.role_ref.name.clone()
        }
    })
}

pub(crate) fn convert_cluster_role_binding_to_grant(cluster_role_binding: &ClusterRoleBinding) -> Result<RBACGrant, Box<dyn Error>> {
    let binding_name = match cluster_role_binding.metadata.name.clone() {
        Some(name) => name,
        None => return Result::Err("cluster role binding was missing name".into())
    };

    Result::Ok(RBACGrant {
        grant_type: GrantType::ClusterRoleBinding,
        namespace: None,
        name: binding_name,
        permissions_id: RBACId {
            rbac_type: IDType::ClusterRole,
            namespace: None,
            name: cluster_role_binding.role_ref.name.clone()
        }
    })
}

pub(crate) fn convert_to_grant_subject(subject: Subject) -> Result<GrantSubject, Box<dyn Error>>{
    let binding_kind = match subject.kind.as_str(){
        "User" => SubjectKind::User,
        "Group" => SubjectKind::Group,
        "ServiceAccount" => SubjectKind::ServiceAccount,
        _ => return Result::Err(format!("kind {} was not a known subject kind", subject.kind).into()),
    };
    let api_group = match subject.api_group{
        Some(group) => group,
        None => "".to_string(),
    };

    Result::Ok(GrantSubject{
        kind: binding_kind,
        name: subject.name.clone(),
        namespace: subject.namespace.clone(),
        api_group
    })
}