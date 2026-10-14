const crypto = require("crypto");

exports.handler = async function (event) {

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }

    try {

        const SUPABASE_URL = process.env.SUPABASE_URL;
        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Missing Supabase environment variables."
            );
        }

        const cookies = event.headers.cookie || "";

        const sessionMatch =
            cookies.match(
                /t-kel_management_session=([^;]+)/
            );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        /*
         * Verify management session
         */

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,management_account_id,expires_at,revoked_at`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
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

        if (
            !sessions.length ||
            sessions[0].revoked_at ||
            new Date(sessions[0].expires_at) <= new Date()
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        /*
         * Load management account
         */

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts?id=eq.${encodeURIComponent(session.management_account_id)}&select=id,management_id,full_name,assigned_role,department,account_status`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!accountResponse.ok) {
            throw new Error(
                "Unable to load management account."
            );
        }

        const accounts =
            await accountResponse.json();

        if (!accounts.length) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account not found."
                })
            };
        }

        const account = accounts[0];

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account is not active."
                })
            };
        }

        /*
         * Only PRO 1 and PRO 2 can use this function.
         */

        const normalizedRole =
    String(account.assigned_role || "")
        .trim()
        .toUpperCase();

if (
    normalizedRole !== "PRO 1" &&
    normalizedRole !== "PRO 2"
) {
    return {
        statusCode: 403,
        headers: {
            "Cache-Control": "no-store"
        },
        body: JSON.stringify({
            success: false,
            message:
                "PRO communication access is restricted."
        })
    };
} {

        /*
         * Get communications created by this PRO.
         */

        const communicationsResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_communications?pro_account_id=eq.${encodeURIComponent(account.id)}&select=id,communication_id,subject,message,priority,director_instruction_id,status,created_at,updated_at&order=created_at.desc`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!communicationsResponse.ok) {
            throw new Error(
                "Unable to load communication history."
            );
        }

        const communications =
            await communicationsResponse.json();

        /*
         * Load recipients for each communication.
         */

        const history = [];

        for (const communication of communications) {

            const recipientsResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communication_recipients?communication_id=eq.${encodeURIComponent(communication.id)}&select=id,recipient_management_id,recipient_name,recipient_role,recipient_email,delivery_status,acknowledged_at,created_at&order=created_at.asc`,
                    {
                        headers: {
                            "apikey": SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        }
                    }
                );

            if (!recipientsResponse.ok) {
                throw new Error(
                    "Unable to load communication recipients."
                );
            }

            const recipients =
                await recipientsResponse.json();

            history.push({
                ...communication,
                recipients
            });
        }

        /*
         * Update session activity.
         */

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json"
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
                "Cache-Control": "no-store",
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                communications: history
            })
        };

    } catch (error) {

        console.error(
            "pro-communication-history error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to load communication history."
            })
        };
    }
};