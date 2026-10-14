const crypto = require("crypto");


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

    const cookies =
        cookieHeader.split(";");


    for (const cookie of cookies) {

        const parts =
            cookie.trim().split("=");

        const key =
            parts.shift();

        if (key === name) {

            return decodeURIComponent(
                parts.join("=")
            );

        }

    }

    return null;
}


exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {

        return {

            statusCode: 405,

            body: JSON.stringify({

                success: false,

                message:
                    "Method not allowed."

            })

        };

    }


    try {

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;


        if (!supabaseUrl || !supabaseKey) {

            throw new Error(
                "Supabase environment variables are missing."
            );

        }


        const sessionToken =
            getCookie(
                event,
                "t-kel_media_manager_session"
            );


        if (sessionToken) {

            const tokenHash =
                hashToken(sessionToken);


            await fetch(

                `${supabaseUrl}/rest/v1/media_manager_sessions` +
                `?token_hash=eq.${encodeURIComponent(
                    tokenHash
                )}`,

                {

                    method: "PATCH",

                    headers: {

                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`,

                        "Content-Type":
                            "application/json",

                        Prefer:
                            "return=minimal"

                    },

                    body: JSON.stringify({

                        revoked_at:
                            new Date().toISOString()

                    })

                }

            );

        }


        return {

            statusCode: 200,

            headers: {

                "Content-Type":
                    "application/json",

                "Set-Cookie":
                    "t-kel_media_manager_session=; " +
                    "HttpOnly; " +
                    "Secure; " +
                    "SameSite=Lax; " +
                    "Path=/; " +
                    "Max-Age=0"

            },

            body: JSON.stringify({

                success: true,

                message:
                    "Media Manager logged out successfully."

            })

        };


    } catch (error) {

        console.error(
            "Media Manager logout error:",
            error
        );


        return {

            statusCode: 500,

            headers: {

                "Content-Type":
                    "application/json"

            },

            body: JSON.stringify({

                success: false,

                message:
                    "An internal server error occurred."

            })

        };

    }

};