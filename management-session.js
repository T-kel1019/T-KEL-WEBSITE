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

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {

        const parts = cookie.trim().split("=");

        const key = parts.shift();

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
                message: "Method not allowed."
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


        const sessionToken =
            getCookie(
                event,
                "t-kel_management_session"
            );


        if (!sessionToken) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message: "Management session required."
                })
            };
        }


        const tokenHash =
            hashToken(sessionToken);


        const sessionResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_sessions` +
                `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
                `&select=id,management_account_id,expires_at,revoked_at`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!sessionResponse.ok) {

            throw new Error(
                "Unable to verify management session."
            );
        }


        const sessions =
            await sessionResponse.json();


        if (!sessions.length) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message: "Invalid Management session."
                })
            };
        }


        const session =
            sessions[0];


        if (session.revoked_at) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message: "This Management session has been revoked."
                })
            };
        }


        if (
            new Date(session.expires_at).getTime()
            <= Date.now()
        ) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message: "Management session has expired."
                })
            };
        }


        const accountResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(session.management_account_id)}` +
                `&select=id,management_id,full_name,email,phone,assigned_role,department,account_status`,
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
                "Unable to retrieve management account."
            );
        }


        const accounts =
            await accountResponse.json();


        if (!accounts.length) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message: "Management account not found."
                })
            };
        }


        const account =
            accounts[0];


        if (account.account_status !== "ACTIVE") {

            return {
                statusCode: 403,
                body: JSON.stringify({
                    success: false,
                    message:
                        `This Management account is ${account.account_status.toLowerCase()}.`
                })
            };
        }


        await fetch(
            `${supabaseUrl}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(session.id)}`,
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
                    last_used_at:
                        new Date().toISOString()
                })
            }
        );


        return {
            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                success: true,

                management: {
                    managementId:
                        account.management_id,

                    fullName:
                        account.full_name,

                    email:
                        account.email,

                    phone:
                        account.phone,

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
            "Management session verification error:",
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