exports.handler = async (event) => {

    if (event.httpMethod !== "GET") {

        return {
            statusCode: 405,

            headers: {
                "Content-Type": "application/json"
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


        // -----------------------------------------
        // GET DIRECTOR ACCESS TOKEN
        // -----------------------------------------

        const authorization =
            event.headers.authorization ||
            event.headers.Authorization ||
            "";


        if (!authorization.startsWith("Bearer ")) {

            return {
                statusCode: 401,

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Director authorization is required."
                })
            };
        }


        const accessToken =
            authorization.substring(7).trim();


        if (!accessToken) {

            return {
                statusCode: 401,

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Director authorization token."
                })
            };
        }


        // -----------------------------------------
        // VERIFY SUPABASE AUTH USER
        // -----------------------------------------

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
                    "Content-Type": "application/json"
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
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Director account could not be verified."
                })
            };
        }


        // -----------------------------------------
        // VERIFY ACTIVE MANAGEMENT DIRECTOR
        // -----------------------------------------

        const directorResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_directors` +
                `?user_id=eq.${encodeURIComponent(directorUser.id)}` +
                `&active=eq.true` +
                `&select=id,user_id,full_name,active`,
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
                "Unable to verify Management Director."
            );
        }


        const directors =
            await directorResponse.json();


        if (!directors.length) {

            return {
                statusCode: 403,

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Management Director authorization required."
                })
            };
        }


        // -----------------------------------------
        // GET MANAGEMENT MEMBERS
        // -----------------------------------------
        //
        // IMPORTANT:
        // password_hash is NOT selected.
        //
        // This function is READ-ONLY.
        // -----------------------------------------

        const membersResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?select=` +
                `id,` +
                `management_id,` +
                `full_name,` +
                `email,` +
                `phone,` +
                `assigned_role,` +
                `department,` +
                `account_status,` +
                `created_by,` +
                `created_at,` +
                `updated_at,` +
                `last_login_at,` +
                `removed_at,` +
                `removed_by,` +
                `removal_reason` +
                `&order=created_at.desc`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!membersResponse.ok) {

            throw new Error(
                "Unable to retrieve Management members."
            );
        }


        const members =
            await membersResponse.json();


        // -----------------------------------------
        // RETURN SAFE MEMBER INFORMATION
        // -----------------------------------------

        const safeMembers =
            members.map((member) => {

                return {

                    id:
                        member.id,

                    managementId:
                        member.management_id,

                    fullName:
                        member.full_name,

                    email:
                        member.email,

                    phone:
                        member.phone,

                    assignedRole:
                        member.assigned_role,

                    department:
                        member.department,

                    accountStatus:
                        member.account_status,

                    createdBy:
                        member.created_by,

                    createdAt:
                        member.created_at,

                    updatedAt:
                        member.updated_at,

                    lastLoginAt:
                        member.last_login_at,

                    removedAt:
                        member.removed_at,

                    removedBy:
                        member.removed_by,

                    removalReason:
                        member.removal_reason
                };
            });


        // -----------------------------------------
        // SUCCESS
        // -----------------------------------------

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

                members:
                    safeMembers,

                count:
                    safeMembers.length
            })
        };


    } catch (error) {

        console.error(
            "Management member list error:",
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
                    "Unable to load Management members."
            })
        };
    }
};