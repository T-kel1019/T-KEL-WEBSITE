exports.handler = async function (event) {

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers: {
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }

    try {

        const SUPABASE_URL = process.env.SUPABASE_URL;
        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Missing Supabase environment variables."
            );
        }

        /*
         * Verify Director Authorization
         */

        const authorization =
            event.headers.authorization ||
            event.headers.Authorization;

        if (
            !authorization ||
            !authorization.startsWith("Bearer ")
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director authorization required."
                })
            };
        }

        const accessToken =
            authorization.substring(7).trim();

        /*
         * Verify Supabase Auth user
         */

        const userResponse = await fetch(
            `${SUPABASE_URL}/auth/v1/user`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${accessToken}`
                }
            }
        );

        if (!userResponse.ok) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Director session."
                })
            };
        }

        const user = await userResponse.json();

        if (!user || !user.id) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Director session."
                })
            };
        }

        /*
         * Confirm active T-KEL Director
         */

        const directorResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(user.id)}&active=eq.true&select=user_id,full_name,active`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!directorResponse.ok) {
            throw new Error(
                "Unable to verify Director access."
            );
        }

        const directors =
            await directorResponse.json();

        if (!directors.length) {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director access denied."
                })
            };
        }

        /*
         * Load communications sent by PRO 1 / PRO 2.
         */

        const communicationsResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_communications?pro_role=in.(${encodeURIComponent("PRO 1")},${encodeURIComponent("PRO 2")})&select=id,communication_id,pro_account_id,pro_management_id,pro_name,pro_role,subject,message,priority,director_instruction_id,status,created_at,updated_at&order=created_at.desc`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!communicationsResponse.ok) {
            const errorText =
                await communicationsResponse.text();

            console.error(
                "PRO communications query failed:",
                errorText
            );

            throw new Error(
                "Unable to load PRO communications."
            );
        }

        const communications =
            await communicationsResponse.json();

        /*
         * Load recipient records for each communication.
         */

        const results = [];

        for (const communication of communications) {

            const recipientsResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communication_recipients?communication_id=eq.${encodeURIComponent(communication.id)}&select=id,recipient_management_account_id,recipient_management_id,recipient_name,recipient_role,recipient_email,delivery_status,acknowledged_at,created_at&order=created_at.asc`,
                    {
                        headers: {
                            "apikey": SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        }
                    }
                );

            if (!recipientsResponse.ok) {
                throw new Error(
                    "Unable to load communication recipients."
                );
            }

            const recipients =
                await recipientsResponse.json();

            results.push({
                ...communication,
                recipients
            });
        }

        return {
            statusCode: 200,
            headers: {
                "Cache-Control": "no-store",
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                communications: results
            })
        };

    } catch (error) {

        console.error(
            "management-director-pro-communications error:",
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
                    "Unable to load PRO communications."
            })
        };
    }
};