const crypto = require("crypto");

exports.handler = async function (event) {

    /*
     * =====================================================
     * T-KEL — PRO SEND COMMUNICATION
     * =====================================================
     *
     * Only ACTIVE PRO 1 or PRO 2 accounts may use this.
     *
     * A PRO may send an official communication to selected
     * active T-KEL management members.
     *
     * The communication can optionally be linked to a
     * Director instruction.
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
       VERIFY MANAGEMENT SESSION
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


    const allowedProRoles = [
        "PRO 1",
        "PRO 2"
    ];


    if (
        !allowedProRoles.includes(
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


    const {
        subject,
        message,
        priority,
        directorInstructionId,
        recipientAccountIds
    } = body;


    /* =====================================================
       CLEAN INPUTS
       ===================================================== */

    const cleanSubject =
        typeof subject === "string"
            ? subject.trim()
            : "";

    const cleanMessage =
        typeof message === "string"
            ? message.trim()
            : "";

    const selectedPriority =
        typeof priority === "string"
            ? priority.trim().toUpperCase()
            : "NORMAL";


    const allowedPriorities = [
        "NORMAL",
        "IMPORTANT",
        "URGENT"
    ];


    /* =====================================================
       VALIDATION
       ===================================================== */

    if (!cleanSubject) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Communication subject is required."
            })
        };
    }


    if (cleanSubject.length > 300) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Communication subject is too long."
            })
        };
    }


    if (!cleanMessage) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Communication message is required."
            })
        };
    }


    if (cleanMessage.length > 10000) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Communication message is too long."
            })
        };
    }


    if (
        !allowedPriorities.includes(
            selectedPriority
        )
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Invalid communication priority."
            })
        };
    }


    /* =====================================================
       OPTIONAL DIRECTOR INSTRUCTION
       ===================================================== */

    let directorInstruction = null;


    if (
        directorInstructionId !== undefined &&
        directorInstructionId !== null &&
        directorInstructionId !== ""
    ) {

        if (
            typeof directorInstructionId !==
            "string"
        ) {

            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Director instruction ID."
                })
            };
        }


        let instructionResponse;


        try {

            instructionResponse =
                await fetch(

                    `${SUPABASE_URL}/rest/v1/pro_director_instructions` +

                    `?id=eq.${encodeURIComponent(directorInstructionId.trim())}` +

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
                        "Unable to verify Director instruction."
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
                        "Unable to verify Director instruction."
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
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director instruction not found or not assigned to this PRO account."
                })
            };
        }


        directorInstruction =
            instructions[0];


        if (
            directorInstruction.status ===
            "CANCELLED"
        ) {

            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "This Director instruction has been cancelled."
                })
            };
        }
    }


    /* =====================================================
       VALIDATE RECIPIENT LIST
       ===================================================== */

    if (
        !Array.isArray(recipientAccountIds) ||
        recipientAccountIds.length < 1
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Select at least one recipient."
            })
        };
    }


    if (
        recipientAccountIds.length > 100
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Too many recipients selected."
            })
        };
    }


    const uniqueRecipientIds =
        [
            ...new Set(
                recipientAccountIds
                    .filter(
                        id =>
                            typeof id ===
                            "string"
                    )
                    .map(
                        id =>
                            id.trim()
                    )
                    .filter(Boolean)
            )
        ];


    if (
        uniqueRecipientIds.length < 1
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Select at least one valid recipient."
            })
        };
    }


    if (
        uniqueRecipientIds.length >
        100
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Too many recipients selected."
            })
        };
    }


    /* =====================================================
       LOAD RECIPIENT ACCOUNTS
       ===================================================== */

    const recipientFilter =
        uniqueRecipientIds
            .map(
                id =>
                    `"${id.replace(
                        /"/g,
                        '\\"'
                    )}"`
            )
            .join(",");


    let recipientResponse;


    try {

        recipientResponse =
            await fetch(

                `${SUPABASE_URL}/rest/v1/management_accounts` +

                `?id=in.(${encodeURIComponent(recipientFilter)})` +

                `&account_status=eq.ACTIVE` +

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
                    "Unable to load recipients."
            })
        };
    }


    if (!recipientResponse.ok) {

        const errorText =
            await recipientResponse.text();

        console.error(
            "PRO recipient lookup failed:",
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
                    "Unable to verify recipients."
            })
        };
    }


    const recipientAccounts =
        await recipientResponse.json();


    if (
        !Array.isArray(recipientAccounts) ||
        recipientAccounts.length !==
            uniqueRecipientIds.length
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "One or more selected recipients are invalid or inactive."
            })
        };
    }


    /* =====================================================
       PREVENT SELF-ONLY CONFUSION
       ===================================================== */

    const otherRecipients =
        recipientAccounts.filter(
            recipient =>
                recipient.id !==
                account.id
        );


    if (
        otherRecipients.length === 0
    ) {

        return {
            statusCode: 400,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Select at least one other T-KEL management member."
            })
        };
    }


    /* =====================================================
       GENERATE COMMUNICATION ID
       ===================================================== */

    const randomPart =
        crypto
            .randomBytes(5)
            .toString("hex")
            .toUpperCase();


    const communicationId =
        `TKEL-PRO-COM-${randomPart}`;


    /* =====================================================
       CREATE COMMUNICATION
       ===================================================== */

    let communicationResponse;


    try {

        communicationResponse =
            await fetch(

                `${SUPABASE_URL}/rest/v1/pro_communications`,

                {
                    method: "POST",

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

                        communication_id:
                            communicationId,

                        pro_account_id:
                            account.id,

                        pro_management_id:
                            account.management_id,

                        pro_name:
                            account.full_name,

                        pro_role:
                            account.assigned_role,

                        subject:
                            cleanSubject,

                        message:
                            cleanMessage,

                        priority:
                            selectedPriority,

                        director_instruction_id:
                            directorInstruction
                                ? directorInstruction.id
                                : null,

                        status:
                            "SENT"
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
                    "Unable to create communication."
            })
        };
    }


    if (!communicationResponse.ok) {

        const errorText =
            await communicationResponse.text();

        console.error(
            "PRO communication insert failed:",
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
                    "Unable to create communication."
            })
        };
    }


    const createdCommunications =
        await communicationResponse.json();


    const communication =
        Array.isArray(
            createdCommunications
        )
            ? createdCommunications[0]
            : null;


    if (!communication) {

        return {
            statusCode: 500,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Communication was not created correctly."
            })
        };
    }


    /* =====================================================
       CREATE RECIPIENT RECORDS
       ===================================================== */

    const recipientRows =
        recipientAccounts.map(
            recipient => ({

                communication_id:
                    communication.id,

                recipient_management_account_id:
                    recipient.id,

                recipient_management_id:
                    recipient.management_id,

                recipient_name:
                    recipient.full_name,

                recipient_role:
                    recipient.assigned_role,

                recipient_email:
                    recipient.email,

                delivery_status:
                    "SENT"
            })
        );


    let recipientsResponse;


    try {

        recipientsResponse =
            await fetch(

                `${SUPABASE_URL}/rest/v1/pro_communication_recipients`,

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

                    body: JSON.stringify(
                        recipientRows
                    )
                }
            );

    } catch (error) {

        console.error(
            "PRO recipient insert failed:",
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
                    "Communication was created, but recipient records could not be completed."
            })
        };
    }


    if (!recipientsResponse.ok) {

        const errorText =
            await recipientsResponse.text();

        console.error(
            "PRO recipient insert failed:",
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
                    "Communication was created, but recipient records could not be completed."
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
                        "SEND_PRO_COMMUNICATION",

                    target_type:
                        "PRO_COMMUNICATION",

                    target_id:
                        communicationId,

                    description:
                        `${account.management_id} (${account.full_name}, ${account.assigned_role}) sent PRO communication ${communicationId} to ${recipientAccounts.length} recipient(s).`
                })
            }
        );

    } catch (error) {

        console.error(
            "PRO communication audit log failed:",
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
        statusCode: 201,

        headers: {
            "Cache-Control": "no-store",

            "Content-Type":
                "application/json"
        },

        body: JSON.stringify({

            success: true,

            message:
                "PRO communication sent successfully.",

            communication: {

                id:
                    communication.id,

                communicationId:
                    communicationId,

                subject:
                    cleanSubject,

                priority:
                    selectedPriority,

                status:
                    "SENT",

                recipientCount:
                    recipientAccounts.length,

                linkedDirectorInstruction:
                    directorInstruction
                        ? directorInstruction.instruction_id
                        : null
            },

            recipients:
                recipientAccounts.map(
                    recipient => ({
                        managementId:
                            recipient.management_id,

                        fullName:
                            recipient.full_name,

                        assignedRole:
                            recipient.assigned_role,

                        department:
                            recipient.department
                    })
                )
        })
    };
};