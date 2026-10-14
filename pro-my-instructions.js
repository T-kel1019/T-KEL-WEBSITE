exports.handler = async function (event) {

    /*
     * =====================================================
     * T-KEL — PRO MY INSTRUCTIONS
     * =====================================================
     *
     * Allows an ACTIVE PRO 1 or PRO 2 management member
     * to view only Director instructions assigned to them.
     *
     * Authentication:
     * T-KEL management session cookie
     *
     * Access:
     * PRO 1
     * PRO 2
     *
     * A PRO officer cannot view another PRO officer's
     * private instructions.
     */


    /* =====================================================
       METHOD CHECK
       ===================================================== */

    if (event.httpMethod !== "GET") {

        return {
            statusCode: 405,

            headers: {
                "Cache-Control": "no-store",
                "Allow": "GET"
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


    if (
        !SUPABASE_URL ||
        !SUPABASE_SECRET_KEY
    ) {

        return {
            statusCode: 500,

            headers: {
                "Cache-Control": "no-store"
            },

            body: JSON.stringify({
                success: false,
                message:
                    "Server configuration error."
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
                part
                    .substring(0, separator)
                    .trim();

            const value =
                part
                    .substring(separator + 1)
                    .trim();

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

    const crypto =
        require("crypto");


    const tokenHash =
        crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");


    /* =====================================================
       VERIFY MANAGEMENT SESSION
       ===================================================== */

    let sessionResponse;


    try {

        sessionResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/management_sessions` +

            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +

            `&revoked_at=is.null` +

            `&expires_at=gt.${encodeURIComponent(new Date().toISOString())}` +

            `&select=id,management_account_id,expires_at`

            ,

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
       ACCOUNT MUST BE ACTIVE
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
       ROLE CHECK
       ===================================================== */

    const normalizedRole =
        String(account.assigned_role || "")
            .trim()
            .toUpperCase();


    const allowedRoles = [
        "PRO 1",
        "PRO 2"
    ];


    if (
        !allowedRoles.includes(
            normalizedRole
        )
    ) {

        return {
            statusCode: 403,

            headers: {
                "Cache-Control": "no-store"
            },

            body: JSON.stringify({
                success: false,
                message:
                    "PRO access required."
            })
        };
    }


    /* =====================================================
       GET ONLY THIS PRO'S INSTRUCTIONS
       ===================================================== */

    let instructionsResponse;


    try {

        instructionsResponse = await fetch(

            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +

            `?assigned_pro_account_id=eq.${encodeURIComponent(account.id)}` +

            `&order=created_at.desc` +

            `&select=id,instruction_id,title,instruction_text,priority,status,director_note,created_at,updated_at`,

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
                    "Unable to load Director instructions."
            })
        };
    }


    if (!instructionsResponse.ok) {

        const errorText =
            await instructionsResponse.text();

        console.error(
            "PRO instructions request failed:",
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
                    "Unable to load Director instructions."
            })
        };
    }


    const instructions =
        await instructionsResponse.json();


    /* =====================================================
       UPDATE LAST USED SESSION
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

            pro: {
                managementId:
                    account.management_id,

                fullName:
                    account.full_name,

                assignedRole:
                    account.assigned_role,

                department:
                    account.department
            },

            instructions:
                instructions
        })
    };
};