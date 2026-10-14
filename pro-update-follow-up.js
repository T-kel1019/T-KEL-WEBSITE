const crypto = require("crypto");

exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {
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
         * Verify Management session.
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
                    message:
                        "Invalid management session."
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
                `${supabaseUrl}/rest/v1/management_accounts?id=eq.${encodeURIComponent(session.management_account_id)}&select=id,management_id,full_name,email,assigned_role,department,account_status`,
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
         * Account must be active.
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
         * Only PRO 1 and PRO 2 may update
         * PRO follow-ups.
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
         * Read request body.
         */
        let body;

        try {
            body =
                JSON.parse(event.body || "{}");
        } catch {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid request body."
                })
            };
        }


        const {
            followUpId,
            status
        } = body;


        if (!followUpId) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up ID is required."
                })
            };
        }


        const allowedStatuses = [
            "OPEN",
            "IN_PROGRESS",
            "COMPLETED",
            "CANCELLED"
        ];


        if (!allowedStatuses.includes(status)) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid follow-up status."
                })
            };
        }


        /*
         * Find the follow-up and make sure
         * it belongs to this PRO.
         */
        const followUpResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?id=eq.${encodeURIComponent(followUpId)}&pro_account_id=eq.${encodeURIComponent(account.id)}&select=id,follow_up_id,title,status,pro_account_id`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!followUpResponse.ok) {
            throw new Error(
                "Unable to retrieve follow-up."
            );
        }


        const followUps =
            await followUpResponse.json();


        if (!followUps.length) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up not found or access denied."
                })
            };
        }


        const followUp =
            followUps[0];


        /*
         * Completed and cancelled follow-ups
         * cannot be reopened by the PRO.
         */
        if (
            followUp.status === "COMPLETED" ||
            followUp.status === "CANCELLED"
        ) {

            if (status !== followUp.status) {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type":
                            "application/json",
                        "Cache-Control":
                            "no-store"
                    },
                    body: JSON.stringify({
                        success: false,
                        message:
                            `This follow-up is already ${followUp.status.toLowerCase()} and cannot be reopened.`
                    })
                };
            }

            return {
                statusCode: 200,
                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },
                body: JSON.stringify({
                    success: true,
                    message:
                        "Follow-up status is already set.",
                    followUp
                })
            };
        }


        /*
         * Prepare update.
         */
        const updateData = {
            status,
            updated_at:
                new Date().toISOString()
        };


        if (status === "COMPLETED") {
            updateData.completed_at =
                new Date().toISOString();
        } else {
            updateData.completed_at = null;
        }


        /*
         * Update follow-up.
         */
        const updateResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?id=eq.${encodeURIComponent(followUp.id)}&pro_account_id=eq.${encodeURIComponent(account.id)}`,
                {
                    method: "PATCH",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`,
                        "Content-Type":
                            "application/json",
                        Prefer:
                            "return=representation"
                    },
                    body:
                        JSON.stringify(updateData)
                }
            );


        if (!updateResponse.ok) {
            throw new Error(
                "Unable to update follow-up."
            );
        }


        const updatedFollowUps =
            await updateResponse.json();


        /*
         * Audit log.
         */
        await fetch(
            `${supabaseUrl}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    apikey: supabaseKey,
                    Authorization:
                        `Bearer ${supabaseKey}`,
                    "Content-Type":
                        "application/json",
                    Prefer: "return=minimal"
                },
                body: JSON.stringify({
                    actor_management_id:
                        account.management_id,
                    actor_role:
                        account.assigned_role,
                    action:
                        "UPDATE_PRO_FOLLOW_UP",
                    target_type:
                        "PRO_FOLLOW_UP",
                    target_id:
                        followUp.follow_up_id,
                    description:
                        `PRO updated follow-up "${followUp.title}" to status ${status}.`
                })
            }
        );


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


        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                message:
                    "Follow-up updated successfully.",
                followUp:
                    updatedFollowUps[0] || null
            })
        };


    } catch (error) {

        console.error(
            "PRO update follow-up error:",
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