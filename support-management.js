const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY;

function json(statusCode, data) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    };
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function getCookie(event, name) {

    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {

        const parts =
            cookie.trim().split("=");

        const key = parts.shift();

        if (key === name) {

            return decodeURIComponent(
                parts.join("=")
            );
        }
    }

    return null;
}


/* =====================================================
   VERIFY T-KEL MANAGEMENT SESSION
===================================================== */

async function verifyManagementSession(event) {

    if (!SUPABASE_URL || !SUPABASE_KEY) {

        throw new Error(
            "Supabase environment variables are missing."
        );
    }

    const sessionToken =
        getCookie(
            event,
            "t-kel_management_session"
        );

    if (!sessionToken) {

        return {
            authorized: false,
            statusCode: 401,
            message:
                "Management session required."
        };
    }

    const tokenHash =
        hashToken(sessionToken);


    const sessionResponse =
        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&select=id,management_account_id,expires_at,revoked_at`,
            {
                method: "GET",

                headers: {
                    apikey: SUPABASE_KEY,
                    Authorization:
                        `Bearer ${SUPABASE_KEY}`
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
            authorized: false,
            statusCode: 401,
            message:
                "Invalid Management session."
        };
    }


    const session =
        sessions[0];


    if (session.revoked_at) {

        return {
            authorized: false,
            statusCode: 401,
            message:
                "This Management session has been revoked."
        };
    }


    if (
        new Date(session.expires_at).getTime()
        <= Date.now()
    ) {

        return {
            authorized: false,
            statusCode: 401,
            message:
                "Management session has expired."
        };
    }


    const accountResponse =
        await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(session.management_account_id)}` +
            `&select=id,management_id,full_name,email,phone,assigned_role,department,account_status`,
            {
                method: "GET",

                headers: {
                    apikey: SUPABASE_KEY,
                    Authorization:
                        `Bearer ${SUPABASE_KEY}`
                }
            }
        );


    if (!accountResponse.ok) {

        throw new Error(
            "Unable to retrieve management account."
        );
    }


    const accounts =
        await accountResponse.json();


    if (!accounts.length) {

        return {
            authorized: false,
            statusCode: 401,
            message:
                "Management account not found."
        };
    }


    const account =
        accounts[0];


    if (
        account.account_status !==
        "ACTIVE"
    ) {

        return {
            authorized: false,
            statusCode: 403,
            message:
                "This Management account is not active."
        };
    }


    const allowedRoles = [
        "Support Team",
        "Monitoring / Supervisor",
        "Founder"
    ];


    if (
        !allowedRoles.includes(
            account.assigned_role
        )
    ) {

        return {
            authorized: false,
            statusCode: 403,
            message:
                "You are not authorized to access Support Management."
        };
    }


    return {
        authorized: true,
        account
    };
}


/* =====================================================
   SUPABASE REQUEST HELPER
===================================================== */

async function supabaseRequest(
    path,
    options = {}
) {

    const response =
        await fetch(
            `${SUPABASE_URL}${path}`,
            {
                ...options,

                headers: {
                    apikey: SUPABASE_KEY,

                    Authorization:
                        `Bearer ${SUPABASE_KEY}`,

                    "Content-Type":
                        "application/json",

                    ...(options.headers || {})
                }
            }
        );


    if (!response.ok) {

        const errorText =
            await response.text();

        throw new Error(
            errorText ||
            "Supabase request failed."
        );
    }


    const text =
        await response.text();

    return text
        ? JSON.parse(text)
        : null;
}


/* =====================================================
   MAIN FUNCTION
===================================================== */

exports.handler = async function(event) {

    if (
        event.httpMethod !==
        "POST"
    ) {

        return json(
            405,
            {
                success: false,
                message:
                    "Method not allowed."
            }
        );
    }


    try {

        const security =
            await verifyManagementSession(
                event
            );


        if (!security.authorized) {

            return json(
                security.statusCode,
                {
                    success: false,
                    message:
                        security.message
                }
            );
        }


        const body =
            JSON.parse(
                event.body || "{}"
            );


        const action =
            body.action;


        /* =================================================
           LIST CONVERSATIONS
        ================================================= */

        if (
            action ===
            "list_conversations"
        ) {

            const conversations =
                await supabaseRequest(
                    `/rest/v1/support_conversations` +
                    `?select=id,visitor_name,visitor_email,visitor_photo,status,created_at,updated_at` +
                    `&order=updated_at.desc`
                );


            return json(
                200,
                {
                    success: true,
                    conversations:
                        conversations || []
                }
            );
        }


        /* =================================================
           GET MESSAGES
        ================================================= */

        if (
            action ===
            "get_messages"
        ) {

            const conversationId =
                body.conversation_id;


            if (!conversationId) {

                return json(
                    400,
                    {
                        success: false,
                        message:
                            "Conversation ID is required."
                    }
                );
            }


            const messages =
                await supabaseRequest(
                    `/rest/v1/support_messages` +
                    `?conversation_id=eq.${encodeURIComponent(conversationId)}` +
                    `&select=id,message,sender_type,sender_name,sender_email,created_at` +
                    `&order=created_at.asc`
                );


            return json(
                200,
                {
                    success: true,
                    messages:
                        messages || []
                }
            );
        }


        /* =================================================
           SEND STAFF MESSAGE
        ================================================= */

        if (
            action ===
            "send_staff_message"
        ) {

            const conversationId =
                body.conversation_id;

            const message =
                (body.message || "")
                    .trim();


            if (
                !conversationId ||
                !message
            ) {

                return json(
                    400,
                    {
                        success: false,
                        message:
                            "Conversation and message are required."
                    }
                );
            }


            const conversations =
                await supabaseRequest(
                    `/rest/v1/support_conversations` +
                    `?id=eq.${encodeURIComponent(conversationId)}` +
                    `&select=id,visitor_name,visitor_email,status`
                );


            if (
                !conversations.length
            ) {

                return json(
                    404,
                    {
                        success: false,
                        message:
                            "Conversation not found."
                    }
                );
            }


            const conversation =
                conversations[0];


            if (
                conversation.status ===
                "closed"
            ) {

                return json(
                    400,
                    {
                        success: false,
                        message:
                            "This conversation is closed."
                    }
                );
            }


            const staff =
                security.account;


            const inserted =
                await supabaseRequest(
                    `/rest/v1/support_messages`,
                    {
                        method: "POST",

                        headers: {
                            Prefer:
                                "return=representation"
                        },

                        body:
                            JSON.stringify({
                                visitor_name:
                                    conversation.visitor_name,

                                visitor_email:
                                    conversation.visitor_email,

                                message:
                                    message,

                                sender_type:
                                    "staff",

                                status:
                                    "open",

                                sender_name:
                                    staff.full_name ||
                                    "T-KEL Support",

                                sender_email:
                                    staff.email ||
                                    "",

                                conversation_id:
                                    conversationId
                            })
                    }
                );


            await supabaseRequest(
                `/rest/v1/support_conversations` +
                `?id=eq.${encodeURIComponent(conversationId)}`,
                {
                    method: "PATCH",

                    headers: {
                        Prefer:
                            "return=minimal"
                    },

                    body:
                        JSON.stringify({
                            status:
                                "active",

                            updated_at:
                                new Date().toISOString()
                        })
                }
            );


            return json(
                200,
                {
                    success: true,
                    message:
                        inserted &&
                        inserted[0]
                            ? inserted[0]
                            : null
                }
            );
        }


        /* =================================================
           CLOSE CONVERSATION
        ================================================= */

        if (
            action ===
            "close_conversation"
        ) {

            const conversationId =
                body.conversation_id;


            if (!conversationId) {

                return json(
                    400,
                    {
                        success: false,
                        message:
                            "Conversation ID is required."
                    }
                );
            }


            await supabaseRequest(
                `/rest/v1/support_conversations` +
                `?id=eq.${encodeURIComponent(conversationId)}`,
                {
                    method: "PATCH",

                    headers: {
                        Prefer:
                            "return=minimal"
                    },

                    body:
                        JSON.stringify({
                            status:
                                "closed",

                            updated_at:
                                new Date().toISOString()
                        })
                }
            );


            return json(
                200,
                {
                    success: true,
                    message:
                        "Conversation closed."
                }
            );
        }


        return json(
            400,
            {
                success: false,
                message:
                    "Unknown support management action."
            }
        );


    } catch (error) {

        console.error(
            "T-KEL Support Management Error:",
            error
        );


        return json(
            500,
            {
                success: false,
                message:
                    "An internal Support Management server error occurred."
            }
        );
    }
};