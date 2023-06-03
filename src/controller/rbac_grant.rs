use std::fmt;
use std::fmt::Formatter;
use std::hash::Hash;
use k8s_openapi::api::rbac::v1::{Role, ClusterRole, RoleBinding, ClusterRoleBinding, Subject};
use kube::ResourceExt;

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

impl RBACId {
    pub fn from_role(role: &Role) -> RBACId{
        RBACId{
            rbac_type: IDType::Role,
            namespace: role.metadata.namespace.clone(),
            name: role.metadata.name.clone().unwrap_or_default(),
        }
    }
    pub fn from_cluster_role(cluster_role: &ClusterRole) -> RBACId{
        RBACId{
            rbac_type: IDType::ClusterRole,
            namespace: cluster_role.metadata.namespace.clone(),
            name: cluster_role.metadata.name.clone().unwrap_or_default()
        }
    }
}

/// Object which grants RBAC permissions. Generic form of role_binding/cluster_role_binding
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct RBACGrant {
    // TODO: Custom hash (and maybe eq?) function which ignores permissions_id.
    /// type of resource which grants RBAC permissions - e.x. role_binding or cluster_role_binding
    pub(crate) grant_type: GrantType,
    /// namespace which the permission grant occurs in - may be none if the grant is cluster-wide
    pub(crate) namespace: Option<String>,
    /// name of the grant - unique within the grant_type for this namespace
    pub(crate) name: String,
    /// the id of the permissions granted by this permissions grant
    pub(crate) permissions_id: RBACId,
}

impl RBACGrant {
    pub fn from_role_binding(role_binding: &RoleBinding) -> RBACGrant{
        let rbac_id = match role_binding.role_ref.kind.as_str(){
            "Role" => RBACId{
                    rbac_type: IDType::Role,
                    namespace: role_binding.metadata.namespace.clone(),
                    name: role_binding.role_ref.name.clone(),
                },
            "ClusterRole" => RBACId{
                    rbac_type: IDType::ClusterRole,
                    namespace: Some("".to_string()),
                    name: role_binding.role_ref.name.clone(),
            },
            _ => RBACId{
                rbac_type: IDType::Unknown,
                namespace: role_binding.metadata.namespace.clone(),
                name: role_binding.role_ref.name.clone(),
            }
        };

        RBACGrant{
            grant_type: GrantType::RoleBinding,
            namespace: role_binding.metadata.namespace.clone(),
            name: role_binding.metadata.name.clone().unwrap_or_default(),
            permissions_id: rbac_id
        }
    }

    pub fn from_cluster_role_binding(binding: &ClusterRoleBinding) -> RBACGrant{
        let rbac_id = match binding.role_ref.kind.as_str(){
            "ClusterRole" => RBACId{
                rbac_type: IDType::ClusterRole,
                namespace: binding.namespace(),
                name: binding.role_ref.name.clone()
            },
            _ => RBACId{
                rbac_type: IDType::Unknown,
                namespace: binding.namespace(),
                name: binding.name(),
            }
        };

        RBACGrant{
            grant_type: GrantType::ClusterRoleBinding,
            namespace: binding.namespace(),
            name: binding.name(),
            permissions_id: rbac_id
        }
    }
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
    Unknown
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
            IDType::Unknown => {
                write!(f, "Unknown")
            }
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

impl GrantSubject {
    pub fn from_subject(subject: &Subject) -> GrantSubject{
        let binding_kind = match subject.kind.as_str(){
            "User" => SubjectKind::User,
            "Group" => SubjectKind::Group,
            "ServiceAccount" => SubjectKind::ServiceAccount,
            _ => SubjectKind::Unknown,
        };
        let api_group = match subject.api_group.clone(){
            Some(group) => group,
            None => "".to_string(),
        };
        GrantSubject{
            kind: binding_kind,
            name: subject.name.clone(),
            namespace: subject.namespace.clone(),
            api_group
        }
    }
}

/// Enum for the ptotential kinds of subjects
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum SubjectKind{
    User,
    Group,
    ServiceAccount,
    Unknown
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
            },
            SubjectKind::Unknown => {
                write!(f, "Unknown")
            },
        }
    }
}
