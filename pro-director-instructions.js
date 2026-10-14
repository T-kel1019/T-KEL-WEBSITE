const crypto = require("crypto");

exports.handler = async function (event) {

    /*
     * =====================================================
     * T-KEL — CREATE PRO DIRECTOR INSTRUCTION
     * =====================================================
     *
     * Only an ACTIVE T-KEL Management Director can use this.
     *
     * The Director can assign an instruction to:
     * - PRO 1
     * - PRO 2
     *
     * The PRO officer cannot create Director instructions.
     */

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
       DIRECTOR AUTHENTICATION
       ===================================================== */

    const authorization =
        event.headers.authorization ||
        event.headers.Authorization ||
        "";

    if (!authorization.startsWith("Bearer ")) {
        return {
            statusCode: 401,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Director authorization required."
            })
        };
    }

    const accessToken =
        authorization.substring(7).trim();


    if (!accessToken) {
        return {
            statusCode: 401,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Director authorization required."
            })
        };
    }


    /* =====================================================
       VERIFY SUPABASE USER
       ===================================================== */

    let authResponse;

    try {

        authResponse = await fetch(
            `${SUPABASE_URL}/auth/v1/user`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${accessToken}`
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
                message: "Authentication service unavailable."
            })
        };
    }


    if (!authResponse.ok) {
        return {
            statusCode: 401,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Invalid director authorization."
            })
        };
    }


    const authUser =
        await authResponse.json();

    const directorUserId =
        authUser.id;


    /* =====================================================
       VERIFY ACTIVE MANAGEMENT DIRECTOR
       ===================================================== */

    let directorResponse;

    try {

        directorResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_directors` +
            `?user_id=eq.${encodeURIComponent(directorUserId)}` +
            `&active=eq.true` +
            `&select=user_id,full_name,active`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
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
                message: "Director verification failed."
            })
        };
    }


    if (!directorResponse.ok) {
        return {
            statusCode: 403,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Director access denied."
            })
        };
    }


    const directors =
        await directorResponse.json();


    if (!Array.isArray(directors) ||
        directors.length !== 1) {

        return {
            statusCode: 403,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Director access denied."
            })
        };
    }


    /* =====================================================
       READ REQUEST
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
                message: "Invalid request data."
            })
        };
    }


    const {
        title,
        instructionText,
        priority,
        assignedProAccountId,
        directorNote
    } = body;


    /* =====================================================
       VALIDATION
       ===================================================== */

    const cleanTitle =
        typeof title === "string"
            ? title.trim()
            : "";

    const cleanInstruction =
        typeof instructionText === "string"
            ? instructionText.trim()
            : "";

    const cleanNote =
        typeof directorNote === "string"
            ? directorNote.trim()
            : "";


    const allowedPriorities = [
        "NORMAL",
        "IMPORTANT",
        "URGENT"
    ];


    const selectedPriority =
        typeof priority === "string"
            ? priority.trim().toUpperCase()
            : "NORMAL";


    if (!cleanTitle) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Instruction title is required."
            })
        };
    }


    if (cleanTitle.length > 300) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Instruction title is too long."
            })
        };
    }


    if (!cleanInstruction) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Instruction text is required."
            })
        };
    }


    if (cleanInstruction.length > 10000) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Instruction is too long."
            })
        };
    }


    if (!allowedPriorities.includes(selectedPriority)) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Invalid instruction priority."
            })
        };
    }


    if (
        typeof assignedProAccountId !== "string" ||
        !assignedProAccountId.trim()
    ) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "A PRO 1 or PRO 2 account must be selected."
            })
        };
    }


    if (cleanNote.length > 5000) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Director note is too long."
            })
        };
    }


    /* =====================================================
       VERIFY SELECTED PRO ACCOUNT
       ===================================================== */

    let proResponse;

    try {

        proResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(assignedProAccountId.trim())}` +
            `&account_status=eq.ACTIVE` +
            `&select=id,management_id,full_name,email,assigned_role,department,account_status`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
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
                    "Unable to verify PRO account."
            })
        };
    }


    if (!proResponse.ok) {
        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to verify PRO account."
            })
        };
    }


    const proAccounts =
        await proResponse.json();


    if (
        !Array.isArray(proAccounts) ||
        proAccounts.length !== 1
    ) {
        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Selected PRO account is not active or does not exist."
            })
        };
    }


    const proAccount =
        proAccounts[0];


    /* =====================================================
       ONLY PRO 1 OR PRO 2 MAY RECEIVE PRO INSTRUCTIONS
       ===================================================== */

    const normalizedRole =
        String(proAccount.assigned_role || "")
            .trim()
            .toUpperCase();


    const allowedProRoles = [
        "PRO 1",
        "PRO 2"
    ];


    if (!allowedProRoles.includes(normalizedRole)) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "The selected account is not a PRO 1 or PRO 2 account."
            })
        };
    }


    /* =====================================================
       GENERATE INSTRUCTION ID
       ===================================================== */

    const randomPart =
        crypto
            .randomBytes(5)
            .toString("hex")
            .toUpperCase();

    const instructionId =
        `TKEL-PRO-INST-${randomPart}`;


    /* =====================================================
       CREATE DIRECTOR INSTRUCTION
       ===================================================== */

    let insertResponse;

    try {

        insertResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_director_instructions`,
            {
                method: "POST",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json",
                    "Prefer":
                        "return=representation"
                },
                body: JSON.stringify({
                    instruction_id:
                        instructionId,

                    title:
                        cleanTitle,

                    instruction_text:
                        cleanInstruction,

                    priority:
                        selectedPriority,

                    assigned_pro_account_id:
                        proAccount.id,

                    created_by:
                        directorUserId,

                    status:
                        "NEW",

                    director_note:
                        cleanNote || null
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
                    "Unable to create Director instruction."
            })
        };
    }


    if (!insertResponse.ok) {

        const errorText =
            await insertResponse.text();

        console.error(
            "PRO instruction insert failed:",
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
                    "Unable to create Director instruction."
            })
        };
    }


    const createdInstructions =
        await insertResponse.json();


    const createdInstruction =
        Array.isArray(createdInstructions)
            ? createdInstructions[0]
            : null;


    /* =====================================================
       AUDIT LOG
       ===================================================== */

    try {

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
                    actor_user_id:
                        directorUserId,

                    actor_management_id:
                        null,

                    actor_role:
                        "Management Director",

                    action:
                        "CREATE_PRO_INSTRUCTION",

                    target_type:
                        "PRO_DIRECTOR_INSTRUCTION",

                    target_id:
                        instructionId,

                    description:
                        `Director created instruction ${instructionId} for ${proAccount.management_id} (${proAccount.full_name}, ${proAccount.assigned_role}).`
                })
            }
        );

    } catch (error) {

        console.error(
            "PRO instruction audit log failed:",
            error
        );
    }


    /* =====================================================
       SUCCESS
       ===================================================== */

    return {
        statusCode: 201,
        headers: {
            "Cache-Control": "no-store",
            "Content-Type":
                "application/json"
        },
        body: JSON.stringify({
            success: true,
            message:
                "PRO instruction created successfully.",

            instruction: {
                id:
                    createdInstruction?.id || null,

                instructionId:
                    instructionId,

                title:
                    cleanTitle,

                priority:
                    selectedPriority,

                assignedTo: {
                    managementId:
                        proAccount.management_id,

                    fullName:
                        proAccount.full_name,

                    assignedRole:
                        proAccount.assigned_role,

                    department:
                        proAccount.department
                },

                status:
                    "NEW"
            }
        })
    };
};