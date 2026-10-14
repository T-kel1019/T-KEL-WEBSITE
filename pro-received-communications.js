const crypto = require("crypto");

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    };

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }

    try {
        // ---------------------------------------------
        // GET SESSION COOKIE
        // ---------------------------------------------

        const cookieHeader = event.headers?.cookie || "";

        const sessionMatch = cookieHeader.match(
            /(?:^|;\s*)t-kel_management_session=([^;]+)/
        );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        // ---------------------------------------------
        // HASH SESSION TOKEN
        // ---------------------------------------------

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        const SUPABASE_URL = process.env.SUPABASE_URL;
        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Supabase environment variables are missing."
            );
        }

        const supabaseHeaders = {
            "apikey": SUPABASE_SECRET_KEY,
            "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`,
            "Content-Type": "application/json"
        };

        // ---------------------------------------------
        // VERIFY SESSION
        // ---------------------------------------------

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(
                new Date().toISOString()
            )}` +
            `&select=id,management_account_id`,
            {
                headers: supabaseHeaders
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
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        // ---------------------------------------------
        // LOAD CURRENT ACCOUNT
        // ---------------------------------------------

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(
                session.management_account_id
            )}` +
            `&select=id,management_id,full_name,email,assigned_role,department,account_status`,
            {
                headers: supabaseHeaders
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
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Management account not found."
                })
            };
        }

        const account = accounts[0];

        // ---------------------------------------------
        // ACCOUNT MUST BE ACTIVE
        // ---------------------------------------------

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account is not active."
                })
            };
        }

        // ---------------------------------------------
        // ONLY PRO 1 AND PRO 2
        // ---------------------------------------------

        const normalizedRole =
            String(account.assigned_role || "")
                .trim()
                .toLowerCase();

        if (
            normalizedRole !== "pro 1" &&
            normalizedRole !== "pro 2"
        ) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Received communications are available only to PRO 1 and PRO 2."
                })
            };
        }

        // ---------------------------------------------
        // LOAD COMMUNICATIONS RECEIVED BY THIS PRO
        // ---------------------------------------------

        const recipientsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_communication_recipients` +
            `?recipient_management_account_id=eq.${encodeURIComponent(
                account.id
            )}` +
            `&select=id,communication_id,recipient_management_id,recipient_name,recipient_role,delivery_status,acknowledged_at,created_at` +
            `&order=created_at.desc`,
            {
                headers: supabaseHeaders
            }
        );

        if (!recipientsResponse.ok) {
            throw new Error(
                "Unable to load received communications."
            );
        }

        const recipientRecords =
            await recipientsResponse.json();

        // ---------------------------------------------
        // LOAD THE ACTUAL COMMUNICATIONS
        // ---------------------------------------------

        const communicationIds =
            recipientRecords
                .map(record => record.communication_id)
                .filter(Boolean);

        let communications = [];

        if (communicationIds.length) {

            const uniqueIds = [
                ...new Set(communicationIds)
            ];

            const idsFilter =
                uniqueIds.join(",");

            const communicationsResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communications` +
                    `?id=in.(${encodeURIComponent(idsFilter)})` +
                    `&select=id,communication_id,pro_account_id,pro_management_id,pro_name,pro_role,subject,message,priority,status,director_instruction_id,created_at,updated_at` +
                    `&order=created_at.desc`,
                    {
                        headers: supabaseHeaders
                    }
                );

            if (!communicationsResponse.ok) {
                throw new Error(
                    "Unable to load communication details."
                );
            }

            communications =
                await communicationsResponse.json();
        }

        // ---------------------------------------------
        // COMBINE RECIPIENT RECORD WITH MESSAGE
        // ---------------------------------------------

        const receivedCommunications =
            recipientRecords.map(recipient => {

                const communication =
                    communications.find(
                        item =>
                            item.id ===
                            recipient.communication_id
                    );

                return {
                    recipientRecordId:
                        recipient.id,

                    communicationId:
                        recipient.communication_id,

                    communicationReference:
                        communication
                            ?.communication_id || null,

                    sender: {
                        managementId:
                            communication
                                ?.pro_management_id ||
                            null,

                        name:
                            communication
                                ?.pro_name ||
                            null,

                        role:
                            communication
                                ?.pro_role ||
                            null
                    },

                    subject:
                        communication
                            ?.subject ||
                        null,

                    message:
                        communication
                            ?.message ||
                        null,

                    priority:
                        communication
                            ?.priority ||
                        "NORMAL",

                    status:
                        communication
                            ?.status ||
                        null,

                    directorInstructionId:
                        communication
                            ?.director_instruction_id ||
                        null,

                    deliveryStatus:
                        recipient.delivery_status,

                    acknowledgedAt:
                        recipient.acknowledged_at,

                    createdAt:
                        recipient.created_at,

                    updatedAt:
                        communication
                            ?.updated_at ||
                        null
                };
            });

        // ---------------------------------------------
        // SUMMARY
        // ---------------------------------------------

        const unreadCount =
            receivedCommunications.filter(
                item =>
                    item.deliveryStatus ===
                    "SENT"
            ).length;

        const acknowledgedCount =
            receivedCommunications.filter(
                item =>
                    item.deliveryStatus ===
                    "ACKNOWLEDGED"
            ).length;

        // ---------------------------------------------
        // UPDATE SESSION ACTIVITY
        // ---------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    ...supabaseHeaders,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    last_used_at:
                        new Date().toISOString()
                })
            }
        );

        // ---------------------------------------------
        // RETURN DATA
        // ---------------------------------------------

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,

                communications:
                    receivedCommunications,

                summary: {
                    total:
                        receivedCommunications.length,

                    unread:
                        unreadCount,

                    acknowledged:
                        acknowledgedCount
                }
            })
        };

    } catch (error) {

        console.error(
            "PRO RECEIVED COMMUNICATIONS ERROR:",
            error
        );

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to load received communications."
            })
        };
    }
};