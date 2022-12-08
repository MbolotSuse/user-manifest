use serde::{Deserialize, Serialize};
use crate::controller::rbac_grant::{RBACGrant, GrantSubject, SubjectKind};

#[derive(Deserialize, Clone)]
pub struct GrantInput{
    pub(crate) name: String,
    pub(crate) namespace: Option<String>,
    pub(crate) user_type: UserType,
    pub(crate) filter: Option<Filter>
}

#[derive(Deserialize, Clone)]
pub struct Filter{
    pub(crate) namespace: Option<String>,
}

#[derive(Deserialize, Clone)]
pub enum UserType{
    ServiceAccount,
    User,
    Group
}

#[derive(Serialize)]
pub struct OutputGrant{
    /// kind of the grant - corresponds to a GrantType
    pub(crate) kind: String,
    pub(crate) name: String
}

impl GrantInput{
    pub fn to_grant_subject(self) -> GrantSubject{
        const HUMAN_USER_API_GROUP: &str = "rbac.authorization.k8s.io";
        let subject_kind: SubjectKind;
        let api_group: String;
        match self.user_type{
            UserType::User => {
                subject_kind = SubjectKind::User;
                api_group = HUMAN_USER_API_GROUP.to_string();
            },
            UserType::Group => {
                subject_kind = SubjectKind::Group;
                api_group = HUMAN_USER_API_GROUP.to_string();
            },
            UserType::ServiceAccount => {
                subject_kind = SubjectKind::ServiceAccount;
                api_group = "".to_string();
            }
        };
        GrantSubject{
            name: self.name,
            namespace: self.namespace,
            kind: subject_kind,
            api_group,
        }
    }
}

pub fn grant_filter_applies(grant: &RBACGrant, filter: &Filter) -> bool{
    match &filter.namespace{
        Some(filter_ns) => {
            match &grant.namespace{
                Some(grant_ns) => *filter_ns == *grant_ns,
                // CRBs don't have namespaces, but they apply across every namespace
                None => true,
            }
        },
        None => true,
    }
}

