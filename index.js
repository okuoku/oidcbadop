const Provider = require("oidc-provider");
const Koa = require("koa");
const KoaMount = require("koa-mount");
const KoaRouter = require("koa-router");
const Jose = require("@panva/jose");
const crypto = require("crypto");
const CookieKeys = new Array(crypto.randomBytes(32));

const issroot = "http://localhost:3000/op";

const keystore = new Jose.JWKS.KeyStore();
keystore.generateSync("RSA", 4096, { alg: "RS256", use: "sig" });
const keystore_jwks = keystore.toJWKS(true);

const oidc_config = {
    jwks: keystore_jwks,
    findAccount: (ctx, id) => {
        return {
            accountId: id,
            claims: (use, scope) => Promise.resolve({sub: id})
        };
    },
    features: {
        introspection: {enabled: true},
        devInteractions: {enabled: false}
    },
    formats: {
        AccessToken: "jwt"
    },
    clients: [{
        client_id: "testing",
        client_secret: "testing",
        redirect_uris: ["https://example.com:80"]
    }],
    interactions: {
        url: (ctx, interaction) => Promise.resolve("/passthrough")
    },
    cookies: {
        keys: CookieKeys,
        short: {signed: true},
        long: {signed: true}
    }
};

const oidc = new Provider(issroot, oidc_config);

async function passthrough(ctx, next){
    const details = await oidc.interactionDetails(ctx.req, ctx.res);
    const result = {
        login: {
            account: "dummy",
            acr: "dummy",
            remember: false,
        },
        consent: {
            rejectedScopes: [],
            rejectedClaims: []
        }
    };
    return oidc.interactionFinished(ctx.req, ctx.res, result);
}

async function result_filter(ctx, next){
    await next();
    if(ctx.oidc.route == "token"){
        let token = ctx.response.body;
        let valid_token = token.id_token;
        let q = Jose.JWT.decode(valid_token);
        q.exp = q.iat - 1;
        let x = Jose.JWT.sign(q, keystore.get({alg: "RS256"}));
        token.id_token = x;
    }
}

const app = new Koa();
const router = new KoaRouter();

// Disable client redirect uri check
oidc.Client.prototype.redirectUriAllowed = (bogus) => true;

router.get("/passthrough", passthrough);
app.use(router.routes())
   .use(router.allowedMethods());
app.use(KoaMount("/op", oidc.app));

oidc.use(result_filter);

app.proxy = true;

app.listen(3000);
