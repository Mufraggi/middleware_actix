mod config;
mod models;

use crate::config::{Config, IConfig};
use crate::models::user::{AuthorizationMiddleware, Claims};
use actix_web::dev::Payload;
use actix_web::error::ErrorUnauthorized;
use actix_web::{Error, FromRequest, HttpRequest};
use futures::future::{err, ok, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};



impl FromRequest for AuthorizationMiddleware {
    type Error = Error;
    type Future = Ready<Result<AuthorizationMiddleware, Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let auth = req.headers().get("Authorization");
        match auth {
            Some(_) => {
                let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
                let token = split[1].trim();
                let config: Config = Config {};
                let var = config.get_config_with_key("SECRET_KEY");
                let key = var.as_bytes();
                match decode::<Claims>(
                    &token.to_string(),
                    &DecodingKey::from_secret(key.as_ref()),
                    &Validation::new(Algorithm::HS256),
                ) {
                    Ok(_token) => {
                        let user_id = _token.claims.user_id;
                        let admin = _token.claims.admin;
                        ok(AuthorizationMiddleware { user_id, admin })
                    }
                    Err(_e) => err(ErrorUnauthorized(_e)),
                }
            }
            None => err(ErrorUnauthorized("Blocked")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{AuthorizationMiddleware};
    use actix_web::body::{Body, ResponseBody};
    use actix_web::error::ErrorUnauthorized;
    use actix_web::http::StatusCode;
    use actix_web::{test, Error, FromRequest, HttpRequest};
    use futures::future::err;
    use serde_json::json;

    #[actix_rt::test]
    async fn from_request_fail_return_invalid() {
        let req: HttpRequest = test::TestRequest::default().to_http_request();
        let mut res = test::TestRequest::to_http_parts(Default::default());
        let resp: Result<AuthorizationMiddleware, Error> =
            AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp = resp.err().unwrap();
        let res_to_check = tmp.as_response_error();
        assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[actix_rt::test]
    async fn form_request_fail_invalid_token() {
        let req: HttpRequest = test::TestRequest::default()
            .header("Authorization", "Bearer text/plain")
            .to_http_request();
        let mut res = test::TestRequest::to_http_parts(Default::default());
        let resp: Result<AuthorizationMiddleware, Error> =
            AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp = resp.err().unwrap();
        let res_to_check = tmp.as_response_error();
        let test: &ResponseBody<Body> = res_to_check.error_response().body();
        assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[actix_rt::test]
    async fn form_request_work() {
        let user_id = "muf";
        let admin = false;
        let token ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcl9pZCI6Im11ZiIsImFkbWluIjpmYWxzZSwiZXhwIjoyMDQyNDU1OTY1fQ.CQlITjRrgcJoKvrHRf-R5Up4oTwGKGvxdmKqtR-Ucdw";
        let req: HttpRequest = test::TestRequest::default()
            .header("Authorization", "Bearer ".to_owned() + token)
            .to_http_request();
        let mut res = test::TestRequest::to_http_parts(Default::default());
        let resp: Result<AuthorizationMiddleware, Error> =
            AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp = resp.unwrap();
        assert_eq!(tmp.user_id, user_id);
        assert_eq!(tmp.admin, admin);
    }
}
