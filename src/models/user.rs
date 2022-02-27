use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String,
    pub admin:bool,
    pub exp: u32,
}

#[derive(Debug)]
pub struct AuthorizationMiddleware {
    pub user_id: String,
    pub admin:bool
}

impl PartialEq for AuthorizationMiddleware {
    fn eq(&self, other: &Self) -> bool {
        self.admin == other.admin && self.user_id == other.user_id
    }
}