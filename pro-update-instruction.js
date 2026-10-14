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
        // LOAD ACCOUNT
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
                        "Only PRO 1 and PRO 2 can update PRO instructions."
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
            instructionId,
            status
        } = body;

        if (!instructionId || !status) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Instruction ID and status are required."
                })
            };
        }

        // ---------------------------------------------
        // ALLOWED STATUSES
        // ---------------------------------------------

        const allowedStatuses = [
            "ACKNOWLEDGED",
            "IN_PROGRESS",
            "COMPLETED"
        ];

        if (!allowedStatuses.includes(status)) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid instruction status."
                })
            };
        }

        // ---------------------------------------------
        // LOAD INSTRUCTION
        // ---------------------------------------------

        const instructionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +
            `?id=eq.${encodeURIComponent(instructionId)}` +
            `&assigned_pro_account_id=eq.${encodeURIComponent(
                account.id
            )}` +
            `&select=id,instruction_id,title,instruction_text,priority,status,director_note,created_at,updated_at`,
            {
                headers: supabaseHeaders
            }
        );

        if (!instructionResponse.ok) {
            throw new Error(
                "Unable to load instruction."
            );
        }

        const instructions =
            await instructionResponse.json();

        if (!instructions.length) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Instruction not found."
                })
            };
        }

        const instruction = instructions[0];

        // ---------------------------------------------
        // CANNOT UPDATE CANCELLED
        // ---------------------------------------------

        if (instruction.status === "CANCELLED") {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Cancelled instructions cannot be updated."
                })
            };
        }

        // ---------------------------------------------
        // COMPLETED INSTRUCTIONS CANNOT BE REOPENED
        // ---------------------------------------------

        if (
            instruction.status === "COMPLETED" &&
            status !== "COMPLETED"
        ) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Completed instructions cannot be reopened."
                })
            };
        }

        // ---------------------------------------------
        // UPDATE INSTRUCTION
        // ---------------------------------------------

        const updateResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +
            `?id=eq.${encodeURIComponent(instruction.id)}` +
            `&assigned_pro_account_id=eq.${encodeURIComponent(
                account.id
            )}`,
            {
                method: "PATCH",
                headers: {
                    ...supabaseHeaders,
                    "Prefer": "return=representation"
                },
                body: JSON.stringify({
                    status,
                    updated_at:
                        new Date().toISOString()
                })
            }
        );

        if (!updateResponse.ok) {
            throw new Error(
                "Unable to update instruction."
            );
        }

        const updatedInstructions =
            await updateResponse.json();

        // ---------------------------------------------
        // AUDIT LOG
        // ---------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    ...supabaseHeaders,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    actor_user_id: null,
                    actor_management_id:
                        account.management_id,
                    actor_role:
                        account.assigned_role,
                    action:
                        "UPDATE_PRO_INSTRUCTION",
                    target_type:
                        "pro_director_instruction",
                    target_id:
                        instruction.id,
                    description:
                        `PRO updated instruction ${instruction.instruction_id} from ${instruction.status} to ${status}.`
                })
            }
        );

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
        // RETURN RESULT
        // ---------------------------------------------

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message:
                    "Instruction status updated successfully.",
                instruction:
                    updatedInstructions[0] || {
                        ...instruction,
                        status
                    }
            })
        };

    } catch (error) {

        console.error(
            "PRO UPDATE INSTRUCTION ERROR:",
            error
        );

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to update instruction."
            })
        };
    }
};