exports.handler = async (event) => {

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
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


        /*
         * Get Director access token.
         */
        const authHeader =
            event.headers.authorization ||
            event.headers.Authorization;

        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management Director authentication required."
                })
            };
        }


        const accessToken =
            authHeader
                .replace("Bearer ", "")
                .trim();


        /*
         * Verify Supabase user.
         */
        const userResponse =
            await fetch(
                `${supabaseUrl}/auth/v1/user`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${accessToken}`
                    }
                }
            );


        if (!userResponse.ok) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid or expired Director session."
                })
            };
        }


        const directorUser =
            await userResponse.json();


        if (!directorUser.id) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director identity could not be verified."
                })
            };
        }


        /*
         * Confirm active Management Director.
         */
        const directorResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(directorUser.id)}&select=user_id,full_name,active`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!directorResponse.ok) {
            throw new Error(
                "Unable to verify Director authorization."
            );
        }


        const directors =
            await directorResponse.json();


        if (
            !directors.length ||
            directors[0].active !== true
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "You are not authorized as an active T-KEL Management Director."
                })
            };
        }


        /*
         * Get all PRO follow-ups.
         */
        const followUpsResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?select=id,follow_up_id,pro_account_id,pro_management_id,pro_name,pro_role,director_instruction_id,communication_id,title,description,priority,status,due_date,completed_at,created_at,updated_at&order=created_at.desc`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!followUpsResponse.ok) {
            throw new Error(
                "Unable to retrieve PRO follow-ups."
            );
        }


        const followUps =
            await followUpsResponse.json();


        /*
         * Only return PRO 1 and PRO 2 records.
         */
        const proFollowUps =
            followUps.filter(
                item =>
                    item.pro_role === "PRO 1" ||
                    item.pro_role === "PRO 2"
            );


        /*
         * Get active PRO accounts.
         */
        const prosResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts?account_status=eq.ACTIVE&assigned_role=in.(PRO%201,PRO%202)&select=id,management_id,full_name,email,phone,assigned_role,department`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!prosResponse.ok) {
            throw new Error(
                "Unable to retrieve PRO members."
            );
        }


        const pros =
            await prosResponse.json();


        /*
         * Summary.
         */
        const summary = {
            total:
                proFollowUps.length,

            open:
                proFollowUps.filter(
                    item =>
                        item.status === "OPEN"
                ).length,

            inProgress:
                proFollowUps.filter(
                    item =>
                        item.status === "IN_PROGRESS"
                ).length,

            completed:
                proFollowUps.filter(
                    item =>
                        item.status === "COMPLETED"
                ).length,

            cancelled:
                proFollowUps.filter(
                    item =>
                        item.status === "CANCELLED"
                ).length,

            overdue:
                proFollowUps.filter(
                    item =>
                        item.due_date &&
                        new Date(item.due_date) < new Date() &&
                        item.status !== "COMPLETED" &&
                        item.status !== "CANCELLED"
                ).length
        };


        return {
            statusCode: 200,
            headers: {
                "Content-Type":
                    "application/json",
                "Cache-Control":
                    "no-store"
            },
            body: JSON.stringify({
                success: true,
                followUps:
                    proFollowUps,
                pros,
                summary
            })
        };


    } catch (error) {

        console.error(
            "Director PRO follow-ups error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type":
                    "application/json",
                "Cache-Control":
                    "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "An internal server error occurred."
            })
        };
    }
};