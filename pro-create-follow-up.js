const crypto = require("crypto");

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    };

    if (event.httpMethod !== "POST") {
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
        // LOAD MANAGEMENT ACCOUNT
        // ---------------------------------------------

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(
                session.management_account_id
            )}` +
            `&select=id,management_id,full_name,assigned_role,account_status`,
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
        // ONLY PRO 1 / PRO 2
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
                        "Only PRO 1 and PRO 2 can create follow-ups."
                })
            };
        }

        // ---------------------------------------------
        // READ REQUEST
        // ---------------------------------------------

        let body;

        try {
            body = JSON.parse(event.body || "{}");
        } catch {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Invalid request body."
                })
            };
        }

        const {
            title,
            description,
            priority,
            dueDate,
            directorInstructionId,
            communicationId
        } = body;

        // ---------------------------------------------
        // VALIDATE TITLE
        // ---------------------------------------------

        if (
            !title ||
            typeof title !== "string" ||
            !title.trim()
        ) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up title is required."
                })
            };
        }

        if (title.trim().length > 200) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up title is too long."
                })
            };
        }

        // ---------------------------------------------
        // VALIDATE DESCRIPTION
        // ---------------------------------------------

        if (
            !description ||
            typeof description !== "string" ||
            !description.trim()
        ) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up description is required."
                })
            };
        }

        if (description.trim().length > 5000) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up description is too long."
                })
            };
        }

        // ---------------------------------------------
        // VALIDATE PRIORITY
        // ---------------------------------------------

        const selectedPriority =
            priority || "NORMAL";

        const allowedPriorities = [
            "NORMAL",
            "IMPORTANT",
            "URGENT"
        ];

        if (
            !allowedPriorities.includes(
                selectedPriority
            )
        ) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid follow-up priority."
                })
            };
        }

        // ---------------------------------------------
        // VALIDATE DUE DATE
        // ---------------------------------------------

        let normalizedDueDate = null;

        if (dueDate) {
            const parsedDate =
                new Date(dueDate);

            if (
                Number.isNaN(
                    parsedDate.getTime()
                )
            ) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        success: false,
                        message:
                            "Invalid due date."
                    })
                };
            }

            normalizedDueDate =
                parsedDate.toISOString();
        }

        // ---------------------------------------------
        // VERIFY DIRECTOR INSTRUCTION
        // ---------------------------------------------

        if (directorInstructionId) {

            const instructionResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_director_instructions` +
                    `?id=eq.${encodeURIComponent(
                        directorInstructionId
                    )}` +
                    `&assigned_pro_account_id=eq.${encodeURIComponent(
                        account.id
                    )}` +
                    `&select=id,status`,
                    {
                        headers:
                            supabaseHeaders
                    }
                );

            if (!instructionResponse.ok) {
                throw new Error(
                    "Unable to verify director instruction."
                );
            }

            const instructions =
                await instructionResponse.json();

            if (!instructions.length) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        success: false,
                        message:
                            "The selected director instruction does not belong to this PRO."
                    })
                };
            }

            if (
                instructions[0].status ===
                "CANCELLED"
            ) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        success: false,
                        message:
                            "A follow-up cannot be attached to a cancelled instruction."
                    })
                };
            }
        }

        // ---------------------------------------------
        // VERIFY COMMUNICATION
        // ---------------------------------------------

        if (communicationId) {

            const communicationResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communications` +
                    `?id=eq.${encodeURIComponent(
                        communicationId
                    )}` +
                    `&pro_account_id=eq.${encodeURIComponent(
                        account.id
                    )}` +
                    `&select=id,status`,
                    {
                        headers:
                            supabaseHeaders
                    }
                );

            if (!communicationResponse.ok) {
                throw new Error(
                    "Unable to verify communication."
                );
            }

            const communications =
                await communicationResponse.json();

            if (!communications.length) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        success: false,
                        message:
                            "The selected communication does not belong to this PRO."
                    })
                };
            }
        }

        // ---------------------------------------------
        // GENERATE FOLLOW-UP ID
        // ---------------------------------------------

        const randomPart =
            crypto
                .randomBytes(5)
                .toString("hex")
                .toUpperCase();

        const followUpId =
            "TKEL-PRO-FU-" + randomPart;

        // ---------------------------------------------
        // CREATE FOLLOW-UP
        // ---------------------------------------------

        const insertResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_follow_ups`,
                {
                    method: "POST",
                    headers: {
                        ...supabaseHeaders,
                        "Prefer":
                            "return=representation"
                    },
                    body: JSON.stringify({
                        follow_up_id:
                            followUpId,

                        pro_account_id:
                            account.id,

                        pro_management_id:
                            account.management_id,

                        pro_name:
                            account.full_name,

                        pro_role:
                            account.assigned_role,

                        director_instruction_id:
                            directorInstructionId ||
                            null,

                        communication_id:
                            communicationId ||
                            null,

                        title:
                            title.trim(),

                        description:
                            description.trim(),

                        priority:
                            selectedPriority,

                        status:
                            "OPEN",

                        due_date:
                            normalizedDueDate
                    })
                }
            );

        if (!insertResponse.ok) {
            const errorText =
                await insertResponse.text();

            console.error(
                "FOLLOW-UP INSERT ERROR:",
                errorText
            );

            throw new Error(
                "Unable to create follow-up."
            );
        }

        const created =
            await insertResponse.json();

        // ---------------------------------------------
        // AUDIT LOG
        // ---------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    ...supabaseHeaders,
                    "Prefer":
                        "return=minimal"
                },
                body: JSON.stringify({
                    actor_user_id:
                        null,

                    actor_management_id:
                        account.management_id,

                    actor_role:
                        account.assigned_role,

                    action:
                        "CREATE_PRO_FOLLOW_UP",

                    target_type:
                        "pro_follow_up",

                    target_id:
                        created[0]?.id ||
                        null,

                    description:
                        `PRO created follow-up ${followUpId}.`
                })
            }
        );

        // ---------------------------------------------
        // UPDATE SESSION ACTIVITY
        // ---------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(
                session.id
            )}`,
            {
                method: "PATCH",
                headers: {
                    ...supabaseHeaders,
                    "Prefer":
                        "return=minimal"
                },
                body: JSON.stringify({
                    last_used_at:
                        new Date().toISOString()
                })
            }
        );

        // ---------------------------------------------
        // RETURN RESULT
        // ---------------------------------------------

        return {
            statusCode: 201,
            headers,
            body: JSON.stringify({
                success: true,
                message:
                    "Follow-up created successfully.",
                followUp:
                    created[0] || null
            })
        };

    } catch (error) {

        console.error(
            "PRO CREATE FOLLOW-UP ERROR:",
            error
        );

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to create follow-up."
            })
        };
    }
};