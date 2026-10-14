const crypto = require("crypto");

exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
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
            throw new Error("Missing Supabase environment variables.");
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
                    message: "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

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

        const sessions = await sessionResponse.json();

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
                    message: "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts?id=eq.${encodeURIComponent(session.management_account_id)}&select=id,management_id,full_name,assigned_role,account_status`,
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

        const accounts = await accountResponse.json();

        if (!accounts.length) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message: "Management account not found."
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
                    message: "Management account is not active."
                })
            };
        }

        const body = JSON.parse(event.body || "{}");

        const {
            communicationRecipientId
        } = body;

        if (!communicationRecipientId) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Communication recipient ID is required."
                })
            };
        }

        /*
         * Find the communication recipient record.
         *
         * The recipient must belong to the currently
         * logged-in management account.
         */

        const recipientResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_communication_recipients?id=eq.${encodeURIComponent(communicationRecipientId)}&recipient_management_account_id=eq.${encodeURIComponent(account.id)}&select=id,communication_id,recipient_management_id,recipient_name,delivery_status`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!recipientResponse.ok) {
            throw new Error(
                "Unable to find communication."
            );
        }

        const recipients =
            await recipientResponse.json();

        if (!recipients.length) {
            return {
                statusCode: 404,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Communication recipient record not found."
                })
            };
        }

        const recipient = recipients[0];

        if (
            recipient.delivery_status ===
            "ACKNOWLEDGED"
        ) {
            return {
                statusCode: 200,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: true,
                    message:
                        "Communication has already been acknowledged."
                })
            };
        }

        /*
         * Mark the communication as acknowledged.
         */

        const updateResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_communication_recipients?id=eq.${encodeURIComponent(communicationRecipientId)}&recipient_management_account_id=eq.${encodeURIComponent(account.id)}`,
            {
                method: "PATCH",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json",
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    delivery_status: "ACKNOWLEDGED",
                    acknowledged_at:
                        new Date().toISOString()
                })
            }
        );

        if (!updateResponse.ok) {
            throw new Error(
                "Unable to acknowledge communication."
            );
        }

        /*
         * Audit log
         */

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    actor_user_id: null,
                    actor_management_id:
                        account.management_id,
                    actor_role:
                        account.assigned_role,
                    action:
                        "ACKNOWLEDGE_PRO_COMMUNICATION",
                    target_type:
                        "PRO_COMMUNICATION",
                    target_id:
                        recipient.communication_id,
                    description:
                        `Management member ${account.management_id} acknowledged a PRO communication.`
                })
            }
        );

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
                message:
                    "Communication acknowledged successfully."
            })
        };

    } catch (error) {

        console.error(
            "pro-acknowledge-communication error:",
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
                    "Unable to acknowledge communication."
            })
        };
    }
};