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
         * Load all PRO instructions.
         */

        const instructionsResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_director_instructions?select=id,instruction_id,title,instruction_text,priority,assigned_pro_account_id,created_by,status,director_note,created_at,updated_at&order=created_at.desc`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!instructionsResponse.ok) {
            const errorText =
                await instructionsResponse.text();

            console.error(
                "PRO instructions query failed:",
                errorText
            );

            throw new Error(
                "Unable to load PRO instructions."
            );
        }

        const instructions =
            await instructionsResponse.json();

        /*
         * Load active PRO accounts so the Director
         * can see the assigned PRO's identity.
         */

        const proAccountsResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_accounts?assigned_role=in.(${encodeURIComponent("PRO 1")},${encodeURIComponent("PRO 2")})&account_status=eq.ACTIVE&select=id,management_id,full_name,assigned_role,department,email`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!proAccountsResponse.ok) {
            throw new Error(
                "Unable to load PRO accounts."
            );
        }

        const proAccounts =
            await proAccountsResponse.json();

        /*
         * Attach safe PRO information to instructions.
         */

        const instructionResults =
            instructions.map(instruction => {

                const assignedPro =
                    proAccounts.find(
                        pro =>
                            pro.id ===
                            instruction.assigned_pro_account_id
                    );

                return {
                    ...instruction,

                    assigned_pro: assignedPro
                        ? {
                            management_id:
                                assignedPro.management_id,
                            full_name:
                                assignedPro.full_name,
                            assigned_role:
                                assignedPro.assigned_role,
                            department:
                                assignedPro.department,
                            email:
                                assignedPro.email
                        }
                        : null
                };
            });

        return {
            statusCode: 200,
            headers: {
                "Cache-Control": "no-store",
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                instructions:
                    instructionResults
            })
        };

    } catch (error) {

        console.error(
            "management-director-pro-instructions error:",
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
                    "Unable to load PRO instructions."
            })
        };
    }
};