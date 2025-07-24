import crypto from "crypto";
import type { Client, IntrospectionResponse, OpenIDCallbackChecks } from "openid-client";
import { Issuer, generators, custom } from "openid-client";
import { v4 } from "uuid";
import type { Request, Response } from "express";
import {
    OPID_CLIENT_ID,
    OPID_CLIENT_SECRET,
    OPID_CLIENT_ISSUER,
    OPID_CLIENT_REDIRECT_URL,
    OPID_USERNAME_CLAIM,
    OPID_LOCALE_CLAIM,
    OPID_SCOPE,
    OPID_PROMPT,
    SECRET_KEY,

    OPID_TAGS_CLAIM,
} from "../enums/EnvironmentVariable";

custom.setHttpOptionsDefaults({
    timeout: 50000,
});

class OpenIDClient {
    private issuerPromise: Promise<Client> | null = null;
    private secret: string;

    constructor() {
        this.secret = crypto.createHash("sha256").update(String(SECRET_KEY)).digest("base64").substring(0, 32);
    }

    private initClient(): Promise<Client> {
        if (!this.issuerPromise) {
            this.issuerPromise = Issuer.discover(OPID_CLIENT_ISSUER)
                .then((issuer) => {
                    return new issuer.Client({
                        client_id: OPID_CLIENT_ID,
                        client_secret: OPID_CLIENT_SECRET,
                        redirect_uris: [OPID_CLIENT_REDIRECT_URL],
                        response_types: ["code"],
                    });
                })
                .catch((e) => {
                    // If this fails, let's try with only the openid-configuration configuration.
                    console.info(
                        "Failed to fetch OIDC configuration for both .well-known/openid-configuration and oauth-authorization-server. Trying .well-known/openid-configuration only."
                    );
                    this.issuerPromise = Issuer.discover(OPID_CLIENT_ISSUER + "/.well-known/openid-configuration")
                        .then((issuer) => {
                            return new issuer.Client({
                                client_id: OPID_CLIENT_ID,
                                client_secret: OPID_CLIENT_SECRET,
                                redirect_uris: [OPID_CLIENT_REDIRECT_URL],
                                response_types: ["code"],
                            });
                        })
                        .catch((e) => {
                            this.issuerPromise = null;
                            throw e;
                        });
                    return this.issuerPromise;
                });
        }
        return this.issuerPromise;
    }

    public authorizationUrl(
        res: Response,
        playUri: string,
        req: Request,
        manuallyTriggered: "true" | undefined,
        chatRoomId: string | undefined,
        providerId: string | undefined,
        providerScopes: string[] | undefined
    ): Promise<string> {
        return this.initClient().then((client) => {
            if (!OPID_SCOPE.includes("email") || !OPID_SCOPE.includes("openid")) {
                throw new Error("Invalid scope, 'email' and 'openid' are required in OPID_SCOPE.");
            }

            const code_verifier = generators.codeVerifier();
            // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
            // it should be httpOnly (not readable by javascript) and encrypted.
            res.cookie("code_verifier", this.encrypt(code_verifier), {
                httpOnly: true, // dont let browser javascript access cookie ever
                secure: req.secure, // only use cookie over https
            });

            // We also store the state in cookies. The state should not be needed, except for older OpenID client servers that
            // don't understand PKCE
            const state = v4();
            res.cookie("oidc_state", state, {
                httpOnly: true, // dont let browser javascript access cookie ever
                secure: req.secure, // only use cookie over https
            });

            const code_challenge = generators.codeChallenge(code_verifier);

            return client.authorizationUrl({
                scope: OPID_SCOPE,
                prompt: OPID_PROMPT,
                state: state,
                //nonce: nonce,
                playUri,
                // Whether the login was triggered by clicking on the "sign in" button (in which case the user was
                // anonymous) or whether the login was triggered because user was not authenticated and authentication
                // is mandatory.
                manuallyTriggered,
                chatRoomId,
                providerId,
                providerScopes,
                code_challenge,
                code_challenge_method: "S256",
            });
        });
    }

    public getUserInfo(
        req: Request,
        res: Response,
        playUri: string
    ): Promise<{
        tags: string[] | undefined;
        email: string;
        sub: string;
        access_token: string;
        username: string;
        locale: string;
        matrix_url: string | undefined;
        matrix_identity_provider: string | undefined;
    }> {
        const fullUrl = req.url;
        const cookies = req.cookies;

        if (typeof cookies?.code_verifier !== "string") {
            console.error("code_verifier cookie is not a string", cookies);
            throw new Error("code verifier doesn't exist");
        }

        console.log("Cookies received for OpenIDClient:", cookies);
        const code_verifier = this.decrypt(cookies.code_verifier);
        const state = cookies.oidc_state;

        console.log("State received for OpenIDClient:", state);
        return this.initClient().then((client) => {
            const params = client.callbackParams(fullUrl);

            const checks: OpenIDCallbackChecks = {
                code_verifier,
            };

            if (state && params.state && typeof state === "string") {
                checks.state = state;
            }

            console.log("Callback parameters for OpenIDClient:", params,
                "URL", OPID_CLIENT_REDIRECT_URL, "Checks", checks
            );

            return client.callback(OPID_CLIENT_REDIRECT_URL, params, checks).then((tokenSet) => {
                console.log("Token set received for OpenIDClient:", tokenSet);
                console.log("Play URI for OpenIDClient:", playUri);

                // res.clearCookie("code_verifier");
                // res.clearCookie("oidc_state");
                const url = `${OPID_CLIENT_ISSUER}/oauth/userinfo`;
                console.log("Fetching user info from:", url);
                return fetch(url, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${tokenSet.access_token}`,
                        'Content-Type': 'application/json',
                    },
                })
                    .then(res => {
                        console.log("Response from userinfo endpoint:", res);

                        if (!res.ok) {
                            throw new Error(`HTTP error! status: ${res.status}`);
                        }

                        return res.json().then(data => {

                            console.log("Data from userinfo endpoint:", data);
                            console.log("OPID_TAGS_CLAIM:", OPID_TAGS_CLAIM, data[OPID_TAGS_CLAIM]);
                            let tags: string[] | undefined;
                            if (data[OPID_TAGS_CLAIM] && Array.isArray(data[OPID_TAGS_CLAIM].tags)) {
                                tags = data[OPID_TAGS_CLAIM].tags;
                            }
                            console.log("Tags extracted:", tags);


                            const result = {
                                email: data.email ?? "",
                                sub: data.sub,
                                access_token: tokenSet.access_token ?? "",
                                username: data[OPID_USERNAME_CLAIM] as string,
                                locale: data[OPID_LOCALE_CLAIM] as string,
                                tags: tags,
                                matrix_url: data.matrix_url as string | undefined,
                                matrix_identity_provider: data.matrix_identity_provider as string | undefined,
                            };
                            console.log("Result from getUserInfo:", result);
                            return result;
                        });
                    }).catch((error) => {
                        console.error("Error fetching user info from userinfo endpoint:", error);
                        throw new Error("Failed to fetch user info from userinfo endpoint");
                    })


                // const userInfo: ClerkUserInfo = await response.json();
                // return userInfo;

                // return client
                //     .userinfo(tokenSet
                //         //, {
                //         //params: {
                //         //    playUri,
                //         //},
                //         //    }
                //     )
                //     .then((res) => {
                //         console.log("User info received for OpenIDClient:", res);
                //         return {
                //             ...res,
                //             email: res.email ?? "",
                //             sub: res.sub,
                //             access_token: tokenSet.access_token ?? "",
                //             username: res[OPID_USERNAME_CLAIM] as string,
                //             locale: res[OPID_LOCALE_CLAIM] as string,
                //             tags: res[OPID_TAGS_CLAIM] as string[],
                //             matrix_url: res.matrix_url as string | undefined,
                //             matrix_identity_provider: res.matrix_identity_provider as string | undefined,
                //         };
                //     }).catch((e) => {
                //         console.error("Error fetching user info:", e);
                //         throw new Error("Failed to fetch user info");
                //     });
            });
        });
    }

    public logoutUser(token: string): Promise<void> {
        return this.initClient().then((client) => {
            if (!client.metadata.revocation_endpoint) {
                return;
            }
            return client.revoke(token);
        });
    }

    public checkTokenAuth(token: string): Promise<IntrospectionResponse> {
        console.log("Checking token auth with token:", token);
        return fetch(`${OPID_CLIENT_ISSUER}/oauth/userinfo`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
        })
            .then(res => {
                console.log("Response from userinfo endpoint:", res);

                if (!res.ok) {
                    throw new Error(`HTTP error! status: ${res.status}`);
                }

                return res.json().then(data => {

                    console.log("Data from userinfo endpoint:", data);
                    console.log("OPID_TAGS_CLAIM:", OPID_TAGS_CLAIM, data[OPID_TAGS_CLAIM]);
                    let tags: string[] | undefined;
                    if (data[OPID_TAGS_CLAIM] && Array.isArray(data[OPID_TAGS_CLAIM].tags)) {
                        tags = data[OPID_TAGS_CLAIM].tags;
                    }
                    console.log("Tags extracted:", tags);

                    const result = {
                        ...res,
                        email: data.email ?? "",
                        sub: data.sub,
                        access_token: token ?? "",
                        username: data[OPID_USERNAME_CLAIM] as string,
                        locale: data[OPID_LOCALE_CLAIM] as string,
                        tags: tags,
                        matrix_url: data.matrix_url as string | undefined,
                        matrix_identity_provider: data.matrix_identity_provider as string | undefined,
                    };
                    console.log("Result from checkTokenAuth:", result);
                    return result;
                });
            }).catch((error) => {
                console.error("Error fetching user info from userinfo endpoint:", error);
                throw new Error("Failed to fetch user info from userinfo endpoint");
            })

        // return this.initClient().then((client) => {
        //     //return client.userinfo(token);
        // });
    }

    private encrypt(text: string): string {
        const iv = crypto.randomBytes(16);
        // @ts-ignore Required because of a bug in svelte-check that is typechecking pusher for some reason
        const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(this.secret), iv);
        let encrypted = cipher.update(text);
        // @ts-ignore Required because of a bug in svelte-check that is typechecking pusher for some reason
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString("hex") + "::" + encrypted.toString("hex");
    }

    private decrypt(data: string): string {
        const parts = data.split("::");
        if (parts.length !== 2) {
            throw new Error("Unexpected encrypted data: " + data);
        }
        const ivStr = parts[0];
        const encryptedData = parts[1];
        const iv = Buffer.from(ivStr, "hex");
        const encryptedText = Buffer.from(encryptedData, "hex");
        // @ts-ignore Required because of a bug in svelte-check that is typechecking pusher for some reason
        const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(this.secret), iv);
        // @ts-ignore Required because of a bug in svelte-check that is typechecking pusher for some reason
        let decrypted = decipher.update(encryptedText);
        // @ts-ignore Required because of a bug in svelte-check that is typechecking pusher for some reason
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }
}

export const openIDClient = new OpenIDClient();
