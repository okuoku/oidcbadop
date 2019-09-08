const Provider = require("oidc-provider");
const Koa = require("koa");
const KoaMount = require("koa-mount");
const KoaRouter = require("koa-router");

const issroot = "http://localhost:3000/op";

const oidc_config = {
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

const app = new Koa();
const router = new KoaRouter();

// Disable client redirect uri check
oidc.Client.prototype.redirectUriAllowed = (bogus) => true;

router.get("/passthrough", passthrough);
app.use(router.routes())
   .use(router.allowedMethods());
app.use(KoaMount("/op", oidc.app));

app.proxy = true;

app.listen(3000);
