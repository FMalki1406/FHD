//! Credentials are caller-supplied and origin-scoped; there is no ambient cookie jar.
use crate::{parse_url, Error};
use reqwest::{
    header::{HeaderValue, AUTHORIZATION, COOKIE},
    RequestBuilder, Url,
};

#[derive(Clone, Default)]
pub struct RequestPolicy {
    pub(crate) authorization: Option<String>,
    pub(crate) cookie: Option<String>,
    pub(crate) redirect_origins: Vec<String>,
}

impl std::fmt::Debug for RequestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestPolicy")
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[redacted]"),
            )
            .field("cookie", &self.cookie.as_ref().map(|_| "[redacted]"))
            .field("redirect_origin_count", &self.redirect_origins.len())
            .finish()
    }
}

impl RequestPolicy {
    /// HTTP credentials require the caller's explicit allow_http permission on Options.
    /// Only exact origins (scheme, host, effective port) may be authorized for redirects.
    pub fn new(
        authorization: Option<String>,
        cookie: Option<String>,
        redirect_origins: Vec<String>,
    ) -> Result<Self, Error> {
        let mut policy = Self {
            authorization,
            cookie,
            redirect_origins,
        };
        policy.validate()?;
        for origin in &mut policy.redirect_origins {
            *origin = parse_url(origin, true)?.origin().ascii_serialization();
        }
        policy.redirect_origins.sort();
        policy.redirect_origins.dedup();
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        for value in [&self.authorization, &self.cookie].into_iter().flatten() {
            if value.is_empty()
                || value.len() > 8192
                || !value.is_ascii()
                || value.bytes().any(|b| b.is_ascii_control())
                || HeaderValue::from_str(value).is_err()
            {
                return Err(Error::InvalidOptions);
            }
        }
        if self.redirect_origins.len() > 8 {
            return Err(Error::InvalidOptions);
        }
        for origin in &self.redirect_origins {
            let url = parse_url(origin, true)?;
            if url.path() != "/" || url.query().is_some() {
                return Err(Error::InvalidOptions);
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_redirect(&self, previous: &Url, next: &Url) -> Result<(), Error> {
        if previous.scheme() == "https" && next.scheme() != "https" {
            return Err(Error::InsecureHttp);
        }
        if previous.origin() != next.origin()
            && !self
                .redirect_origins
                .iter()
                .any(|origin| *origin == next.origin().ascii_serialization())
        {
            return Err(Error::RedirectOriginChange);
        }
        Ok(())
    }

    pub(crate) fn apply(
        &self,
        mut request: RequestBuilder,
        target: &Url,
        initial: &Url,
    ) -> Result<RequestBuilder, Error> {
        if target.origin() == initial.origin() {
            for (name, value) in [(AUTHORIZATION, &self.authorization), (COOKIE, &self.cookie)] {
                if let Some(value) = value {
                    let mut value =
                        HeaderValue::from_str(value).map_err(|_| Error::InvalidOptions)?;
                    value.set_sensitive(true);
                    request = request.header(name, value);
                }
            }
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_rejects_injection_paths_unbounded_inputs_and_downgrades() {
        for secret in ["", "Bearer secret\r\nHost: attacker", "x\ty"] {
            assert!(RequestPolicy::new(Some(secret.into()), None, vec![]).is_err());
        }
        assert!(RequestPolicy::new(Some("x".repeat(8193)), None, vec![]).is_err());
        for origin in [
            "https://example.com/a",
            "https://example.com/?token=s",
            "https://u:p@example.com",
        ] {
            assert!(RequestPolicy::new(None, None, vec![origin.into()]).is_err());
        }
        let policy = RequestPolicy::new(
            Some("Bearer PRIVATE".into()),
            Some("session=SECRET".into()),
            vec!["http://example.com".into()],
        )
        .unwrap();
        assert!(!format!("{policy:?}").contains("PRIVATE"));
        assert!(!format!("{policy:?}").contains("SECRET"));
        assert_eq!(
            policy.authorize_redirect(
                &Url::parse("https://example.com").unwrap(),
                &Url::parse("http://example.com").unwrap()
            ),
            Err(Error::InsecureHttp)
        );
    }
}
