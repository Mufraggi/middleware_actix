mod config;
mod models;

use actix_web::{Error, FromRequest, HttpRequest};
use actix_web::dev::Payload;
use actix_web::error::ErrorUnauthorized;
use futures::future::{err, ok, Ready};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use crate::config::{Config, IConfig};
use crate::models::user::Claims;


#[derive(Debug)]
pub struct AuthorizationMiddleware;


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
                    Ok(_token) => ok(AuthorizationMiddleware),
                    Err(_e) => {
                        _e;
                        err(ErrorUnauthorized("Invalid token"))}
                }
            }
            None => err(ErrorUnauthorized("Blocked"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use actix_web::{FromRequest, HttpRequest, test, Error};
    use crate::AuthorizationMiddleware;
     use actix_web::http::{StatusCode};

    #[actix_rt::test]
    async fn from_request_fail_return_invalid() {
        let req: HttpRequest = test::TestRequest::default().to_http_request();
        /*let req: HttpRequest = test::TestRequest::default().header("Authorization", "Bearer text/plain")
            .to_http_request();*/
        let mut  res = test::TestRequest::to_http_parts(Default::default());
        let _authorization_middleware = AuthorizationMiddleware;
        let resp: Result<AuthorizationMiddleware, Error> = AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp= resp.err().unwrap();
        let res_to_check = tmp.as_response_error();
        assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[actix_rt::test]
    async fn form_request_fail_invalid_token() {
        let req: HttpRequest = test::TestRequest::default().header("Authorization", "Bearer text/plain")
            .to_http_request();
        let mut  res = test::TestRequest::to_http_parts(Default::default());
        let _authorization_middleware = AuthorizationMiddleware;
        let resp: Result<AuthorizationMiddleware, Error> = AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp= resp.err().unwrap();
        let res_to_check = tmp.as_response_error();
        assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[actix_rt::test]
    async fn form_request_work() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyMDQyNDU1OTY1fQ.CidfmYA9fyd65ZRqc-uzMoFKfUliYZZY79Nnz-R4JTE";
        let req: HttpRequest = test::TestRequest::default().header("Authorization", "Bearer ".to_owned() + token)
            .to_http_request();
        let mut  res = test::TestRequest::to_http_parts(Default::default());
        let _authorization_middleware = AuthorizationMiddleware;
        let resp: Result<AuthorizationMiddleware, Error> = AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp= resp.unwrap();
        //let res_to_check = tmp.as_response_error();
        //assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
}
