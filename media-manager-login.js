const crypto = require("crypto");


function scryptAsync(password, salt) {

    return new Promise((resolve, reject) => {

        crypto.scrypt(
            password,
            salt,
            64,
            (err, derivedKey) => {

                if (err) {
                    reject(err);
                } else {
                    resolve(derivedKey);
                }

            }
        );

    });

}


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {

        return {
            statusCode: 405,

            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };

    }


    try {

        const {
            mediaManagerId,
            password
        } = JSON.parse(event.body || "{}");


        if (!mediaManagerId || !password) {

            return {
                statusCode: 400,

                body: JSON.stringify({
                    success: false,
                    message:
                        "Media Manager ID and password are required."
                })
            };

        }


        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;


        if (!supabaseUrl || !supabaseKey) {

            throw new Error(
                "Supabase environment variables are missing."
            );

        }


        /*
         * Find the account using the existing
         * management_accounts table.
         */

        const accountResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?management_id=eq.${encodeURIComponent(
                    mediaManagerId.trim()
                )}` +
                `&select=*`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!accountResponse.ok) {

            throw new Error(
                "Unable to retrieve Media Manager account."
            );

        }


        const accounts =
            await accountResponse.json();


        if (!accounts.length) {

            return {
                statusCode: 401,

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Media Manager ID or password."
                })
            };

        }


        const account =
            accounts[0];


        /*
         * Make sure this account is actually
         * assigned to the Media Manager role.
         */

        if (
            String(account.assigned_role || "")
                .trim()
                .toLowerCase() !==
            "media manager"
        ) {

            return {
                statusCode: 403,

                body: JSON.stringify({
                    success: false,
                    message:
                        "This account is not assigned to the Media Manager role."
                })
            };

        }


        /*
         * Only ACTIVE accounts can log in.
         */

        if (account.account_status !== "ACTIVE") {

            return {
                statusCode: 403,

                body: JSON.stringify({
                    success: false,
                    message:
                        `This Media Manager account is ${String(
                            account.account_status || "inactive"
                        ).toLowerCase()}.`
                })
            };

        }


        const storedHash =
            account.password_hash;


        if (
            !storedHash ||
            !storedHash.startsWith("scrypt:")
        ) {

            throw new Error(
                "Invalid password storage format."
            );

        }


        const parts =
            storedHash.split(":");


        if (parts.length !== 3) {

            throw new Error(
                "Invalid password storage format."
            );

        }


        const salt =
            parts[1];


        const storedDerivedKey =
            Buffer.from(
                parts[2],
                "hex"
            );


        const suppliedDerivedKey =
            await scryptAsync(
                password,
                salt
            );


        if (
            storedDerivedKey.length !==
                suppliedDerivedKey.length ||

            !crypto.timingSafeEqual(
                storedDerivedKey,
                suppliedDerivedKey
            )
        ) {

            return {
                statusCode: 401,

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Media Manager ID or password."
                })
            };

        }


        /*
         * Create a separate Media Manager session.
         */

        const sessionToken =
            crypto.randomBytes(48).toString("hex");


        const tokenHash =
            hashToken(sessionToken);


        const expiresAt =
            new Date(
                Date.now() +
                7 * 24 * 60 * 60 * 1000
            ).toISOString();


        const sessionResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/media_manager_sessions`,
                {
                    method: "POST",

                    headers: {
                        apikey: supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`,

                        "Content-Type":
                            "application/json",

                        Prefer:
                            "return=minimal"
                    },

                    body: JSON.stringify({

                        management_account_id:
                            account.id,

                        token_hash:
                            tokenHash,

                        expires_at:
                            expiresAt

                    })
                }
            );


        if (!sessionResponse.ok) {

            throw new Error(
                "Failed to create Media Manager session."
            );

        }


        /*
         * Update last login time.
         */

        await fetch(
            `${supabaseUrl}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(account.id)}`,

            {
                method: "PATCH",

                headers: {
                    apikey: supabaseKey,

                    Authorization:
                        `Bearer ${supabaseKey}`,

                    "Content-Type":
                        "application/json",

                    Prefer:
                        "return=minimal"
                },

                body: JSON.stringify({

                    last_login_at:
                        new Date().toISOString(),

                    updated_at:
                        new Date().toISOString()

                })
            }
        );


        return {

            statusCode: 200,

            headers: {

                "Content-Type":
                    "application/json",

                "Set-Cookie":
                    `t-kel_media_manager_session=${sessionToken}; ` +
                    `HttpOnly; ` +
                    `Secure; ` +
                    `SameSite=Lax; ` +
                    `Path=/; ` +
                    `Max-Age=604800`

            },

            body: JSON.stringify({

                success: true,

                message:
                    "Media Manager login successful.",

                mediaManager: {

                    mediaManagerId:
                        account.management_id,

                    fullName:
                        account.full_name,

                    assignedRole:
                        account.assigned_role,

                    department:
                        account.department,

                    accountStatus:
                        account.account_status

                }

            })

        };


    } catch (error) {

        console.error(
            "Media Manager login error:",
            error
        );


        return {

            statusCode: 500,

            body: JSON.stringify({

                success: false,

                message:
                    "An internal server error occurred."

            })

        };

    }

};