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
         * Get Director Authorization header.
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

        if (!accessToken) {
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

        /*
         * Verify Supabase Auth user.
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
         * Confirm the user is an active
         * T-KEL Management Director.
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
         * Load PRO reports.
         *
         * Only PRO 1 and PRO 2 reports are returned.
         */

        const reportsResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_director_reports?pro_role=in.(${encodeURIComponent("PRO 1")},${encodeURIComponent("PRO 2")})&select=id,report_id,pro_account_id,pro_management_id,pro_name,pro_role,director_instruction_id,communication_id,report_title,report_text,outcome,follow_up_required,status,director_response,created_at,updated_at&order=created_at.desc`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!reportsResponse.ok) {
            const errorText =
                await reportsResponse.text();

            console.error(
                "PRO reports query failed:",
                errorText
            );

            throw new Error(
                "Unable to load PRO reports."
            );
        }

        const reports =
            await reportsResponse.json();

        /*
         * Return reports to Director.
         */

        return {
            statusCode: 200,
            headers: {
                "Cache-Control": "no-store",
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                reports
            })
        };

    } catch (error) {

        console.error(
            "management-director-pro-reports error:",
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
                    "Unable to load PRO reports."
            })
        };
    }
};