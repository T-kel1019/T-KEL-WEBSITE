const crypto = require("crypto");

exports.handler = async function (event) {

    /*
     * =====================================================
     * T-KEL — PRO ACKNOWLEDGE DIRECTOR INSTRUCTION
     * =====================================================
     *
     * Only an ACTIVE PRO 1 or PRO 2 account can acknowledge
     * an instruction assigned to that same account.
     */


    /* =====================================================
       METHOD CHECK
       ===================================================== */

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: {
                "Cache-Control": "no-store",
                "Allow": "POST"
            },
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }


    /* =====================================================
       ENVIRONMENT VARIABLES
       ===================================================== */

    const SUPABASE_URL =
        process.env.SUPABASE_URL;

    const SUPABASE_SECRET_KEY =
        process.env.SUPABASE_SECRET_KEY;


    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Server configuration error."
            })
        };
    }


    /* =====================================================
       READ MANAGEMENT SESSION COOKIE
       ===================================================== */

    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies = {};

    cookieHeader
        .split(";")
        .forEach(function (part) {

            const separator =
                part.indexOf("=");

            if (separator === -1) {
                return;
            }

            const name =
                part.substring(0, separator).trim();

            const value =
                part.substring(separator + 1).trim();

            if (name) {
                cookies[name] = value;
            }
        });


    const sessionToken =
        cookies.t-kel_management_session;


    if (!sessionToken) {
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


    /* =====================================================
       HASH SESSION TOKEN
       ===================================================== */

    const tokenHash =
        crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");


    /* =====================================================
       VERIFY SESSION
       ===================================================== */

    let sessionResponse;

    try {

        sessionResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(new Date().toISOString())}` +
            `&select=id,management_account_id,expires_at`,

            {
                method: "GET",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,

                    "Content-Type":
                        "application/json"
                }
            }
        );

    } catch (error) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Session verification failed."
            })
        };
    }


    if (!sessionResponse.ok) {

        return {
            statusCode: 401,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Invalid management session."
            })
        };
    }


    const sessions =
        await sessionResponse.json();


    if (
        !Array.isArray(sessions) ||
        sessions.length !== 1
    ) {

        return {
            statusCode: 401,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Invalid or expired management session."
            })
        };
    }


    const session =
        sessions[0];


    /* =====================================================
       GET MANAGEMENT ACCOUNT
       ===================================================== */

    let accountResponse;

    try {

        accountResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(session.management_account_id)}` +
            `&select=id,management_id,full_name,email,assigned_role,department,account_status`,

            {
                method: "GET",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,

                    "Content-Type":
                        "application/json"
                }
            }
        );

    } catch (error) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to verify management account."
            })
        };
    }


    if (!accountResponse.ok) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to verify management account."
            })
        };
    }


    const accounts =
        await accountResponse.json();


    if (
        !Array.isArray(accounts) ||
        accounts.length !== 1
    ) {

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


    const account =
        accounts[0];


    /* =====================================================
       ACTIVE ACCOUNT CHECK
       ===================================================== */

    if (
        account.account_status !==
        "ACTIVE"
    ) {

        return {
            statusCode: 403,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "This management account is not active."
            })
        };
    }


    /* =====================================================
       PRO ROLE CHECK
       ===================================================== */

    const normalizedRole =
        String(account.assigned_role || "")
            .trim()
            .toUpperCase();


    const allowedRoles = [
        "PRO 1",
        "PRO 2"
    ];


    if (!allowedRoles.includes(normalizedRole)) {

        return {
            statusCode: 403,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "PRO 1 or PRO 2 access required."
            })
        };
    }


    /* =====================================================
       READ REQUEST BODY
       ===================================================== */

    let body;

    try {

        body = JSON.parse(
            event.body || "{}"
        );

    } catch (error) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Invalid request data."
            })
        };
    }


    const instructionId =
        typeof body.instructionId === "string"
            ? body.instructionId.trim()
            : "";


    if (!instructionId) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Instruction ID is required."
            })
        };
    }


    /* =====================================================
       FIND INSTRUCTION
       ===================================================== */

    let instructionResponse;

    try {

        instructionResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +

            `?id=eq.${encodeURIComponent(instructionId)}` +

            `&assigned_pro_account_id=eq.${encodeURIComponent(account.id)}` +

            `&select=id,instruction_id,title,status`,

            {
                method: "GET",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,

                    "Content-Type":
                        "application/json"
                }
            }
        );

    } catch (error) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to find Director instruction."
            })
        };
    }


    if (!instructionResponse.ok) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to find Director instruction."
            })
        };
    }


    const instructions =
        await instructionResponse.json();


    if (
        !Array.isArray(instructions) ||
        instructions.length !== 1
    ) {

        return {
            statusCode: 404,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Instruction not found or not assigned to this account."
            })
        };
    }


    const instruction =
        instructions[0];


    /* =====================================================
       CHECK CURRENT STATUS
       ===================================================== */

    if (
        instruction.status === "CANCELLED"
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "This instruction has been cancelled."
            })
        };
    }


    if (
        instruction.status === "COMPLETED"
    ) {

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
                    "This instruction has already been completed.",
                instructionId:
                    instruction.instruction_id,
                status:
                    "COMPLETED"
            })
        };
    }


    /* =====================================================
       UPDATE TO ACKNOWLEDGED
       ===================================================== */

    let updateResponse;

    try {

        updateResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +

            `?id=eq.${encodeURIComponent(instruction.id)}` +

            `&assigned_pro_account_id=eq.${encodeURIComponent(account.id)}`,

            {
                method: "PATCH",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,

                    "Content-Type":
                        "application/json",

                    "Prefer":
                        "return=representation"
                },

                body: JSON.stringify({
                    status:
                        "ACKNOWLEDGED",

                    updated_at:
                        new Date().toISOString()
                })
            }
        );

    } catch (error) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to acknowledge instruction."
            })
        };
    }


    if (!updateResponse.ok) {

        const errorText =
            await updateResponse.text();

        console.error(
            "PRO instruction acknowledgement failed:",
            errorText
        );

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to acknowledge instruction."
            })
        };
    }


    /* =====================================================
       AUDIT LOG
       ===================================================== */

    try {

        await fetch(

            `${SUPABASE_URL}/rest/v1/management_audit_logs`,

            {
                method: "POST",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,

                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    actor_user_id:
                        null,

                    actor_management_id:
                        account.management_id,

                    actor_role:
                        account.assigned_role,

                    action:
                        "ACKNOWLEDGE_PRO_INSTRUCTION",

                    target_type:
                        "PRO_DIRECTOR_INSTRUCTION",

                    target_id:
                        instruction.instruction_id,

                    description:
                        `${account.management_id} (${account.full_name}) acknowledged Director instruction ${instruction.instruction_id}.`
                })
            }
        );

    } catch (error) {

        console.error(
            "PRO acknowledgement audit log failed:",
            error
        );
    }


    /* =====================================================
       UPDATE SESSION ACTIVITY
       ===================================================== */

    try {

        await fetch(

            `${SUPABASE_URL}/rest/v1/management_sessions` +

            `?id=eq.${encodeURIComponent(session.id)}`,

            {
                method: "PATCH",

                headers: {
                    "apikey":
                        SUPABASE_SECRET_KEY,

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

    } catch (error) {

        console.error(
            "Unable to update session activity:",
            error
        );
    }


    /* =====================================================
       SUCCESS
       ===================================================== */

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
                "Director instruction acknowledged successfully.",

            instruction: {
                instructionId:
                    instruction.instruction_id,

                title:
                    instruction.title,

                status:
                    "ACKNOWLEDGED"
            },

            pro: {
                managementId:
                    account.management_id,

                fullName:
                    account.full_name,

                assignedRole:
                    account.assigned_role
            }
        })
    };
};