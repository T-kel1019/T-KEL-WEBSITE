const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Method not allowed"
            })
        };
    }

    try {

        const body = JSON.parse(event.body || "{}");

        const action = body.action;


        /* =====================================
           CREATE NEW SUPPORT CONVERSATION
        ===================================== */

        if (action === "create_conversation") {

            const visitorName =
                (body.visitor_name || "").trim();

            const visitorEmail =
                (body.visitor_email || "").trim();

            const visitorPhoto =
                body.visitor_photo || null;


            if (!visitorName || !visitorEmail) {

                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        error:
                            "Name and email are required."
                    })
                };

            }


            const visitorToken =
                crypto.randomUUID();


            const {
                data,
                error
            } = await supabase
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


            return {

                statusCode: 200,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    success: true,

                    conversation_id:
                        data.id,

                    visitor_token:
                        visitorToken

                })

            };

        }


        /* =====================================
           SEND VISITOR MESSAGE
        ===================================== */

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

                return {

                    statusCode: 400,

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        error:
                            "Conversation, visitor token and message are required."

                    })

                };

            }


            /* =================================
               VERIFY THE VISITOR'S CONVERSATION
            ================================= */

            const {

                data: conversation,

                error:
                    conversationError

            } = await supabase

                .from("support_conversations")

                .select("id, visitor_name, visitor_email")

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

                return {

                    statusCode: 403,

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        error:
                            "Invalid support conversation."

                    })

                };

            }


            /* =================================
               SAVE THE MESSAGE
            ================================= */

            const {

                data,
                error

            } = await supabase

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


            /* =================================
               UPDATE CONVERSATION
            ================================= */

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


            return {

                statusCode: 200,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    success: true,

                    message: data

                })

            };

        }


        /* =====================================
           UNKNOWN ACTION
        ===================================== */

        return {

            statusCode: 400,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                error:
                    "Unknown support action."

            })

        };


    } catch (error) {

        console.error(
            "T-KEL Support Error:",
            error
        );


        return {

            statusCode: 500,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                error:
                    "T-KEL Support server error."

            })

        };

    }

};