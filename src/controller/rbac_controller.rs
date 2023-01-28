use crate::controller::grant_controller::GrantController;
use crate::controller::permission_controller::PermissionController;

pub struct RBACController{
    pub(crate) grant_controller: GrantController,
    pub(crate) permission_controller: PermissionController
}