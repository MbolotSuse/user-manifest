use serde::Serialize;
use crate::controller::rbac_grant::{RBACGrant, RBACId, GrantSubject};

// To maintain proper encapsulation the user-facing versions of structs
// differ from the internal-facing versions of the structs

// OutputGrant is the user-facing version of RBACGrant
#[derive(Serialize, Clone)]
pub struct OutputGrant{
    pub grant_type: String,
    pub namespace: String,
    pub name: String,
    pub rbac_id: OutputId,
}

// OutputID is the user-facing version of RBACId
#[derive(Serialize, Clone)]
pub struct OutputId{
    pub name: String,
    pub namespace: String,
    pub rbac_type: String,
}

// OutputSubject is the user-facing version of GrantSubject
#[derive(Serialize, Clone)]
pub struct OutputSubject{
    pub api_group: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
}

impl OutputGrant {
    pub(crate) fn from_rbac_grant(grant: RBACGrant) -> OutputGrant{
        return OutputGrant { 
            grant_type: grant.grant_type.to_string(), 
            namespace: grant.namespace.unwrap_or("*".to_string()), 
            name: grant.name, 
            rbac_id: OutputId::from_rbac_id(grant.permissions_id), 
        }
    }
}

impl OutputId {
    pub(crate) fn from_rbac_id(id: RBACId) -> OutputId{
        return OutputId { 
            name: id.name, 
            namespace: id.namespace.unwrap_or("".to_string()), 
            rbac_type: id.rbac_type.to_string(),
        }
    }
}

impl OutputSubject{
    pub(crate) fn from_grant_subject(subject: GrantSubject) -> OutputSubject{
        return OutputSubject { 
            api_group: subject.api_group, 
            kind: subject.kind.to_string(), 
            name: subject.name, 
            namespace: subject.namespace.unwrap_or("".to_string()) 
        }
    }
}
