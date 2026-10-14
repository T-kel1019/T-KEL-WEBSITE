exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {
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


        /* Director authentication */
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
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
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


        /* Verify Supabase user */
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
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
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
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director identity could not be verified."
                })
            };
        }


        /* Confirm active Director */
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
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "You are not authorized as an active T-KEL Management Director."
                })
            };
        }


        /* Read request body */
        let body;

        try {
            body =
                JSON.parse(event.body || "{}");
        } catch {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid request body."
                })
            };
        }


        const {
            followUpId,
            status,
            directorResponse: rawDirectorResponse
        } = body;


        if (!followUpId) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Follow-up ID is required."
                })
            };
        }


        const allowedStatuses = [
            "OPEN",
            "IN_PROGRESS",
            "COMPLETED",
            "CANCELLED"
        ];

        if (!allowedStatuses.includes(status)) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid follow-up status."
                })
            };
        }


        const directorResponseText =
            typeof rawDirectorResponse === "string"
                ? rawDirectorResponse.trim()
                : "";


        if (directorResponseText.length > 5000) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director response is too long."
                })
            };
        }


        /* Retrieve follow-up */
        const followUpResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?id=eq.${encodeURIComponent(followUpId)}&select=id,follow_up_id,pro_account_id,pro_management_id,pro_name,pro_role,title,status`,
                {
                    method: "GET",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );

        if (!followUpResponse.ok) {
            throw new Error(
                "Unable to retrieve PRO follow-up."
            );
        }

        const followUps =
            await followUpResponse.json();

        if (!followUps.length) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "PRO follow-up not found."
                })
            };
        }

        const followUp =
            followUps[0];


        /* Only PRO follow-ups */
        if (
            followUp.pro_role !== "PRO 1" &&
            followUp.pro_role !== "PRO 2"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "This is not a PRO follow-up."
                })
            };
        }


        /*
         * Do not reopen completed or cancelled
         * follow-ups.
         */
        if (
            (
                followUp.status === "COMPLETED" ||
                followUp.status === "CANCELLED"
            ) &&
            status !== followUp.status
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        `This follow-up is already ${followUp.status.toLowerCase()} and cannot be reopened.`
                })
            };
        }


        /* Prepare update */
        const updateData = {
            status,
            updated_at:
                new Date().toISOString()
        };

        if (status === "COMPLETED") {
            updateData.completed_at =
                new Date().toISOString();
        } else {
            updateData.completed_at = null;
        }

        if (directorResponseText) {
            updateData.director_response =
                directorResponseText;
        }


        /* Update follow-up */
        const updateResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/pro_follow_ups?id=eq.${encodeURIComponent(followUp.id)}`,
                {
                    method: "PATCH",
                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`,
                        "Content-Type":
                            "application/json",
                        Prefer:
                            "return=representation"
                    },
                    body:
                        JSON.stringify(updateData)
                }
            );

        if (!updateResponse.ok) {
            throw new Error(
                "Unable to update PRO follow-up."
            );
        }

        const updatedFollowUps =
            await updateResponse.json();


        /* Audit log */
        await fetch(
            `${supabaseUrl}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    apikey: supabaseKey,
                    Authorization:
                        `Bearer ${supabaseKey}`,
                    "Content-Type":
                        "application/json",
                    Prefer:
                        "return=minimal"
                },
                body: JSON.stringify({
                    actor_user_id:
                        directorUser.id,
                    actor_role:
                        "Management Director",
                    action:
                        "UPDATE_PRO_FOLLOW_UP",
                    target_type:
                        "PRO_FOLLOW_UP",
                    target_id:
                        followUp.follow_up_id,
                    description:
                        `Director updated PRO follow-up "${followUp.title}" for ${followUp.pro_name} (${followUp.pro_role}) to ${status}.`
                })
            }
        );


        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                message:
                    "PRO follow-up updated successfully.",
                followUp:
                    updatedFollowUps[0] || null
            })
        };


    } catch (error) {

        console.error(
            "Director PRO follow-up action error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "An internal server error occurred."
            })
        };
    }
};