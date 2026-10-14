const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);

function json(statusCode, data) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    };
}

exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
        return json(405, {
            error: "Method not allowed"
        });
    }

    try {

        const body =
            JSON.parse(event.body || "{}");

        const action =
            body.action;


        /* =====================================================
           CREATE CONVERSATION
        ===================================================== */

        if (action === "create_conversation") {

            const visitorName =
                (body.visitor_name || "").trim();

            const visitorEmail =
                (body.visitor_email || "").trim();

            const visitorPhoto =
                body.visitor_photo || null;


            if (!visitorName || !visitorEmail) {

                return json(400, {
                    error:
                        "Name and email are required."
                });

            }


            const visitorToken =
                crypto.randomUUID();


            const {
                data,
                error
            } =
                await supabase
                    .from("support_conversations")
                    .insert({

                        visitor_name:
                            visitorName,

                        visitor_email:
                            visitorEmail,

                        visitor_photo:
                            visitorPhoto,

                        visitor_token:
                            visitorToken,

                        status:
                            "waiting"

                    })
                    .select()
                    .single();


            if (error) {
                throw error;
            }


            return json(200, {

                success:
                    true,

                conversation_id:
                    data.id,

                visitor_token:
                    visitorToken

            });

        }


        /* =====================================================
           SEND VISITOR MESSAGE
        ===================================================== */

        if (action === "send_message") {

            const conversationId =
                body.conversation_id;

            const visitorToken =
                body.visitor_token;

            const message =
                (body.message || "").trim();


            if (
                !conversationId ||
                !visitorToken ||
                !message
            ) {

                return json(400, {
                    error:
                        "Conversation, visitor token and message are required."
                });

            }


            const {
                data: conversation,
                error: conversationError
            } =
                await supabase
                    .from("support_conversations")
                    .select(`
                        id,
                        visitor_name,
                        visitor_email,
                        visitor_token,
                        status
                    `)
                    .eq(
                        "id",
                        conversationId
                    )
                    .eq(
                        "visitor_token",
                        visitorToken
                    )
                    .single();


            if (
                conversationError ||
                !conversation
            ) {

                return json(403, {
                    error:
                        "Invalid support conversation."
                });

            }


            if (
                conversation.status ===
                "closed"
            ) {

                return json(400, {
                    error:
                        "This support conversation is closed."
                });

            }


            const {
                data,
                error
            } =
                await supabase
                    .from("support_messages")
                    .insert({

                        visitor_name:
                            conversation.visitor_name,

                        visitor_email:
                            conversation.visitor_email,

                        message:
                            message,

                        sender_type:
                            "visitor",

                        status:
                            "open",

                        sender_name:
                            conversation.visitor_name,

                        sender_email:
                            conversation.visitor_email,

                        conversation_id:
                            conversationId

                    })
                    .select()
                    .single();


            if (error) {
                throw error;
            }


            await supabase
                .from("support_conversations")
                .update({

                    status:
                        "active",

                    updated_at:
                        new Date().toISOString()

                })
                .eq(
                    "id",
                    conversationId
                );


            return json(200, {

                success:
                    true,

                message:
                    data

            });

        }


        /* =====================================================
           GET VISITOR MESSAGES
        ===================================================== */

        if (action === "get_messages") {

            const conversationId =
                body.conversation_id;

            const visitorToken =
                body.visitor_token;


            if (
                !conversationId ||
                !visitorToken
            ) {

                return json(400, {
                    error:
                        "Conversation and visitor token are required."
                });

            }


            const {
                data: conversation,
                error: conversationError
            } =
                await supabase
                    .from("support_conversations")
                    .select("id")
                    .eq(
                        "id",
                        conversationId
                    )
                    .eq(
                        "visitor_token",
                        visitorToken
                    )
                    .single();


            if (
                conversationError ||
                !conversation
            ) {

                return json(403, {
                    error:
                        "Invalid support conversation."
                });

            }


            const {
                data: messages,
                error
            } =
                await supabase
                    .from("support_messages")
                    .select(`
                        id,
                        message,
                        sender_type,
                        sender_name,
                        created_at
                    `)
                    .eq(
                        "conversation_id",
                        conversationId
                    )
                    .order(
                        "created_at",
                        {
                            ascending: true
                        }
                    );


            if (error) {
                throw error;
            }


            return json(200, {

                success:
                    true,

                messages:
                    messages || []

            });

        }


        return json(400, {
            error:
                "Unknown support action."
        });


    } catch (error) {

        console.error(
            "T-KEL Support Error:",
            error
        );


        return json(500, {
            error:
                "T-KEL Support server error."
        });

    }

};