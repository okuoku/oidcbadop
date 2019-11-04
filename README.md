BAD OpenID Connect RP Demo
==========================

Demo: https://oidcbadop-client.glitch.me/ (Actual RP is at `oidcbadop.glitch.me`)

This is a malicious OpenID Connect RP demo code that has 3 scenarios:

- `Valid` - Return valid JWT for anyone
- `Expire` - Return expired certificate. Currently it will give expired before 120 sec. from request time. See also [Issue 3](https://github.com/okuoku/oidcbadop/issues/3).
- `Algnone` - Return `alg = none` JWT.

This OP is intentionally configured as an open redirector. It accepts any `redirect_uri` parameter on its token endpoint.

Usage
-----

Add as normal OIDC provider with:

- `client_id` = `testing`
- `client_secret` = `testing`
- Redirect URI: (Any URI is accepted)
- Discovery with: https://oidcbadop.glitch.me/op/.well-known/openid-configuration

ToDo / FIXME
------------

- Externally controllable modification mode for test automation.
- More modification modes. Perhaps `Expire` can be 1 sec depth.
- Support more auth flow, especially Implicit Flow.

