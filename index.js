const Provider = require("oidc-provider");
const Koa = require("koa");
const KoaMount = require("koa-mount");
const KoaRouter = require("koa-router");
const KoaEjs = require("koa-ejs");
const Jose = require("@panva/jose");
const crypto = require("crypto");
const path = require("path");
const DummyCookieKeys = new Array(crypto.randomBytes(32).toString("base64"));

const issroot = "http://localhost:3000/op";

const keystore = new Jose.JWKS.KeyStore();
keystore.generateSync("RSA", 4096, { alg: "RS256", use: "sig" });
const keystore_jwks = keystore.toJWKS(true);

const oidc_config = {
    jwks: keystore_jwks,
    findAccount: (ctx, id) => {
        return {
            accountId: "dummy",
            claims: (use, scope) => Promise.resolve({sub: "dummy", modify: id})
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
        redirect_uris: ["https://example.com:80"],
        default_max_age: 1 /* Always request login */
    }],
    interactions: {
        url: (ctx, interaction) => Promise.resolve("/gate")
    },
    cookies: {
        keys: DummyCookieKeys, // FIXME: Sign cookies
        short: {signed: false},
        long: {signed: false}
    },
    // Custom id_token claim(s)
    claims: {
        // Standard claims
        acr: null,
        iss: null,
        auth_time: null,
        sid: null,
        // Custom: "modify" claim to modify output JWT
        openid: [
            "sub", "modify",
        ]
    }
};

const ejs_config = {
    root: path.join(__dirname, "view"),
    layout: "_base",
    viewExt: "html",
    cache: true,
    debug: true
};

const oidc = new Provider(issroot, oidc_config);

async function gate(ctx, next){
    return ctx.render("chooser");
}

async function chooser(ctx, next){
    const details = await oidc.interactionDetails(ctx.req, ctx.res);
    let choice = "dummy";
    if(ctx.params.choice){
        choice = ctx.params.choice;
    }
    const result = {
        login: {
            account: choice,
            acr: "0",
            remember: false,
        },
        consent: {
            rejectedScopes: [],
            rejectedClaims: []
        }
    };

    return oidc.interactionFinished(ctx.req, ctx.res, result);
}

function base64jwt(obj){
    const str = JSON.stringify(obj);
    const orig = Buffer.from(str).toString("base64");
    return orig.replace(/=/g,"");
}

// FIXME: Implement catchall

async function result_filter(ctx, next){
    await next();
    if(ctx.oidc.route == "token"){
        let token = ctx.response.body;
        const valid_token = token.id_token;
        if(valid_token){
            let q = Jose.JWT.decode(valid_token);
            switch(q.modify){
                case "expire":
                    q.exp = q.iat - 1;
                    token.id_token = 
                        Jose.JWT.sign(q, keystore.get({alg: "RS256"}));
                    break;
                case "algnone":
                    token.id_token =
                        base64jwt({typ: "JWT", alg: "none"})
                        +
                        "."
                        +
                        base64jwt(q)
                        +
                        ".";
                    break;
                default:
                    /* Do nothing */
                    break;
            }
        }
    }
}

const app = new Koa();
const router = new KoaRouter();

// Disable client redirect uri check
oidc.Client.prototype.redirectUriAllowed = (bogus) => true;

router.get("/gate", gate);
router.get("/gate/chooser/:choice", chooser); // Need to be under "/gate"
app.use(router.routes())
   .use(router.allowedMethods());

oidc.use(result_filter);
KoaEjs(app, ejs_config);
app.use(KoaMount("/op", oidc.app));

app.proxy = true;

app.listen(3000);
