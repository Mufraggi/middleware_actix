use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    pub admin:bool,
    pub exp: u32,
}

#[derive(Debug)]
pub struct AuthorizationMiddleware {
    pub user_id: String,
    pub admin:bool
}