use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String,
    pub admin:bool,
    pub exp: u32,
}

#[derive(Debug, PartialEq)]
pub struct AuthorizationMiddleware {
    pub user_id: String,
    pub admin:bool
}
