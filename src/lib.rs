mod config;
mod models;

pub use crate::config::{Config, IConfig};
pub use crate::models::user::{AuthorizationMiddleware, Claims};
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
                let config: Config = Config {path: "src/config/config.env".to_string() };
                let var = "Xqv8jTGLxT";
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
    use chrono::{ Duration, Utc};
    use crate::{AuthorizationMiddleware, Claims, Config, IConfig};
    use actix_web::http::StatusCode;
    use actix_web::{test, Error, FromRequest, HttpRequest};
    use jsonwebtoken::{encode, EncodingKey, Header};

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
        assert_eq!(res_to_check.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[actix_rt::test]
    async fn form_request_work() {
        let user_id = "muf".to_string() ;
        let admin = false;
        let date = Utc::now() + Duration::hours(1);
        let my_claims = Claims {
            user_id,
            admin,
            exp: date.timestamp() as u32,
        };
        let config: Config = Config {path: "src/config/config.env".to_string() };
        let token = encode(
            &Header::default(),
            &my_claims,
            &EncodingKey::from_secret(config.get_config_with_key("SECRET_KEY").as_ref()),
        )
            .unwrap();
        let req: HttpRequest = test::TestRequest::default()
            .header("Authorization", "Bearer ".to_owned() + &token)
            .to_http_request();
        let mut res = test::TestRequest::to_http_parts(Default::default());
        let resp: Result<AuthorizationMiddleware, Error> =
            AuthorizationMiddleware::from_request(&req, &mut res.1).await;
        let tmp = resp.unwrap();
        assert_eq!(tmp.eq(&AuthorizationMiddleware{
             user_id: "muf".to_string(),
            admin:false
        }), true)
    }
}
