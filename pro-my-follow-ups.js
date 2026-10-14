const crypto = require("crypto");

exports.handler = async (event) => {

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
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


        /*
         * Get Management session cookie.
         */
        const cookieHeader =
            event.headers.cookie ||
            event.headers.Cookie ||
            "";

        const sessionMatch =
            cookieHeader.match(
                /t-kel_management_session=([^;]+)/
            );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message: "Management login required."
                })
            };
        }

        const sessionToken =
            sessionMatch[1];


        /*
         * Hash session token.
         */
        const tokenHash =
            crypto
                .createHash("sha256")
                .update(sessionToken)
                .digest("hex");


        /*
         * Find active session.
         */
        const sessionResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,management_account_id,expires_at,revoked_at`,
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
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message: "Invalid management session."
                })
            };
        }


        const session =
            sessions[0];


        /*
         * Check session expiration.
         */
        if (
            session.revoked_at ||
            new Date(session.expires_at) <= new Date()
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session has expired."
                })
            };
        }


        /*
         * Get Management account.
         */
        const accountResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts?id=eq.${encodeURIComponent(session.management_account_id)}&select=id,management_id,full_name,email,phone,assigned_role,department,account_status`,
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
                "Unable to retrieve Management account."
            );
        }


        const accounts =
            await accountResponse.json();


        if (!accounts.length) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account could not be found."
                })
            };
        }


        const account =
            accounts[0];


        /*
         * Only active accounts may access
         * PRO follow-ups.
         */
        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Your Management account is not active."
                })
            };
        }


        /*
         * Only PRO 1 and PRO 2 may access
         * this endpoint.
         */
        if (
            account.assigned_role !== "PRO 1" &&
            account.assigned_role !== "PRO 2"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "PRO access is required."
                })
            };
        }


        /*
         * Get follow-ups belonging to this PRO.
         */
        const followUpsResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?pro_account_id=eq.${encodeURIComponent(account.id)}&select=id,follow_up_id,pro_account_id,pro_management_id,pro_name,pro_role,director_instruction_id,communication_id,title,description,priority,status,due_date,completed_at,created_at,updated_at&order=created_at.desc`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!followUpsResponse.ok) {
            throw new Error(
                "Unable to retrieve PRO follow-ups."
            );
        }


        const followUps =
            await followUpsResponse.json();


        /*
         * Update session activity.
         */
        await fetch(
            `${supabaseUrl}/rest/v1/management_sessions?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    apikey: supabaseKey,
                    Authorization:
                        `Bearer ${supabaseKey}`,
                    "Content-Type":
                        "application/json",
                    Prefer: "return=minimal"
                },
                body: JSON.stringify({
                    last_used_at:
                        new Date().toISOString()
                })
            }
        );


        /*
         * Summary counts.
         */
        const summary = {
            total: followUps.length,
            open: followUps.filter(
                item => item.status === "OPEN"
            ).length,
            inProgress: followUps.filter(
                item => item.status === "IN_PROGRESS"
            ).length,
            completed: followUps.filter(
                item => item.status === "COMPLETED"
            ).length,
            cancelled: followUps.filter(
                item => item.status === "CANCELLED"
            ).length
        };


        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                account: {
                    managementId:
                        account.management_id,
                    fullName:
                        account.full_name,
                    role:
                        account.assigned_role,
                    department:
                        account.department
                },
                followUps,
                summary
            })
        };


    } catch (error) {

        console.error(
            "PRO follow-ups error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "An internal server error occurred."
            })
        };
    }
};