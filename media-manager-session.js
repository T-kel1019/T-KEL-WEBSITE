const crypto = require("crypto");


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


function getCookie(event, name) {

    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies =
        cookieHeader.split(";");


    for (const cookie of cookies) {

        const parts =
            cookie.trim().split("=");

        const key =
            parts.shift();


        if (key === name) {

            return decodeURIComponent(
                parts.join("=")
            );

        }

    }


    return null;

}


exports.handler = async (event) => {

    if (event.httpMethod !== "GET") {

        return {

            statusCode: 405,

            body: JSON.stringify({

                success: false,

                message:
                    "Method not allowed."

            })

        };

    }


    try {

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
         * Get the Media Manager's
         * separate session cookie.
         */

        const sessionToken =
            getCookie(
                event,
                "t-kel_media_manager_session"
            );


        if (!sessionToken) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Media Manager session required."

                })

            };

        }


        const tokenHash =
            hashToken(sessionToken);


        /*
         * Find the Media Manager session.
         */

        const sessionResponse =
            await fetch(

                `${supabaseUrl}/rest/v1/media_manager_sessions` +

                `?token_hash=eq.${encodeURIComponent(
                    tokenHash
                )}` +

                `&select=id,management_account_id,expires_at,revoked_at`,

                {

                    method: "GET",

                    headers: {

                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`

                    }

                }

            );


        if (!sessionResponse.ok) {

            throw new Error(
                "Unable to verify Media Manager session."
            );

        }


        const sessions =
            await sessionResponse.json();


        if (!sessions.length) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Invalid Media Manager session."

                })

            };

        }


        const session =
            sessions[0];


        /*
         * Check whether the session
         * has been revoked.
         */

        if (session.revoked_at) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "This Media Manager session has been revoked."

                })

            };

        }


        /*
         * Check whether the session
         * has expired.
         */

        if (

            new Date(
                session.expires_at
            ).getTime() <= Date.now()

        ) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Media Manager session has expired."

                })

            };

        }


        /*
         * Retrieve the account connected
         * to this Media Manager session.
         */

        const accountResponse =
            await fetch(

                `${supabaseUrl}/rest/v1/management_accounts` +

                `?id=eq.${encodeURIComponent(
                    session.management_account_id
                )}` +

                `&select=id,management_id,full_name,email,phone,assigned_role,department,account_status`,

                {

                    method: "GET",

                    headers: {

                        apikey:
                            supabaseKey,

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
                        "Media Manager account not found."

                })

            };

        }


        const account =
            accounts[0];


        /*
         * Make sure the account still
         * belongs to the Media Manager role.
         */

        if (

            String(
                account.assigned_role || ""
            )
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
         * Make sure the account is still active.
         */

        if (
            account.account_status !== "ACTIVE"
        ) {

           const crypto = require("crypto");


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


function getCookie(event, name) {

    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies =
        cookieHeader.split(";");


    for (const cookie of cookies) {

        const parts =
            cookie.trim().split("=");

        const key =
            parts.shift();


        if (key === name) {

            return decodeURIComponent(
                parts.join("=")
            );

        }

    }


    return null;

}


exports.handler = async (event) => {

    if (event.httpMethod !== "GET") {

        return {

            statusCode: 405,

            body: JSON.stringify({

                success: false,

                message:
                    "Method not allowed."

            })

        };

    }


    try {

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
         * Get the Media Manager's
         * separate session cookie.
         */

        const sessionToken =
            getCookie(
                event,
                "t-kel_media_manager_session"
            );


        if (!sessionToken) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Media Manager session required."

                })

            };

        }


        const tokenHash =
            hashToken(sessionToken);


        /*
         * Find the Media Manager session.
         */

        const sessionResponse =
            await fetch(

                `${supabaseUrl}/rest/v1/media_manager_sessions` +

                `?token_hash=eq.${encodeURIComponent(
                    tokenHash
                )}` +

                `&select=id,management_account_id,expires_at,revoked_at`,

                {

                    method: "GET",

                    headers: {

                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`

                    }

                }

            );


        if (!sessionResponse.ok) {

            throw new Error(
                "Unable to verify Media Manager session."
            );

        }


        const sessions =
            await sessionResponse.json();


        if (!sessions.length) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Invalid Media Manager session."

                })

            };

        }


        const session =
            sessions[0];


        /*
         * Check whether the session
         * has been revoked.
         */

        if (session.revoked_at) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "This Media Manager session has been revoked."

                })

            };

        }


        /*
         * Check whether the session
         * has expired.
         */

        if (

            new Date(
                session.expires_at
            ).getTime() <= Date.now()

        ) {

            return {

                statusCode: 401,

                body: JSON.stringify({

                    success: false,

                    message:
                        "Media Manager session has expired."

                })

            };

        }


        /*
         * Retrieve the account connected
         * to this Media Manager session.
         */

        const accountResponse =
            await fetch(

                `${supabaseUrl}/rest/v1/management_accounts` +

                `?id=eq.${encodeURIComponent(
                    session.management_account_id
                )}` +

                `&select=id,management_id,full_name,email,phone,assigned_role,department,account_status`,

                {

                    method: "GET",

                    headers: {

                        apikey:
                            supabaseKey,

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
                        "Media Manager account not found."

                })

            };

        }


        const account =
            accounts[0];


        /*
         * Make sure the account still
         * belongs to the Media Manager role.
         */

        if (

            String(
                account.assigned_role || ""
            )
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
         * Make sure the account is still active.
         */

        if (
            account.account_status !== "ACTIVE"
        ) {

           