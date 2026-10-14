const crypto = require("crypto");

exports.handler = async function (event) {

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Method not allowed."
            })
        };
    }

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Server configuration error."
            })
        };
    }

    try {

        // -----------------------------------------
        // GET DIRECTOR AUTH TOKEN
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
                    error: "Director authentication required."
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
                    error: "Invalid authentication token."
                })
            };
        }

        // -----------------------------------------
        // VERIFY SUPABASE AUTH USER
        // -----------------------------------------

        const userResponse = await fetch(
            `${SUPABASE_URL}/auth/v1/user`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${accessToken}`
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
                    error: "Invalid Director session."
                })
            };
        }

        const user = await userResponse.json();

        if (!user || !user.id) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Invalid Director session."
                })
            };
        }

        // -----------------------------------------
        // VERIFY ACTIVE MANAGEMENT DIRECTOR
        // -----------------------------------------

        const directorResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_directors` +
            `?user_id=eq.${encodeURIComponent(user.id)}` +
            `&active=eq.true` +
            `&select=user_id,full_name,active`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!directorResponse.ok) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Director authorization check failed."
                })
            };
        }

        const directors = await directorResponse.json();

        if (!directors.length) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Director access denied."
                })
            };
        }

        const director = directors[0];

        // -----------------------------------------
        // GET ALL MANAGEMENT REPORTS
        // -----------------------------------------

        const reportsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_reports` +
            `?select=id,report_id,management_account_id,management_id,staff_name,assigned_role,department,report_type,description,status,assigned_to,director_response,created_at,updated_at,resolved_at` +
            `&order=created_at.desc`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!reportsResponse.ok) {

            const errorText =
                await reportsResponse.text();

            console.error(
                "Director reports query error:",
                errorText
            );

            throw new Error(
                "Unable to load management reports."
            );
        }

        const reports =
            await reportsResponse.json();

        // -----------------------------------------
        // GET ACTIVE MANAGEMENT MEMBERS
        // -----------------------------------------
        // This allows the Director interface to show
        // members who can receive an assignment.

        const membersResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?account_status=eq.ACTIVE` +
            `&select=id,management_id,full_name,assigned_role,department` +
            `&order=full_name.asc`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!membersResponse.ok) {

            const errorText =
                await membersResponse.text();

            console.error(
                "Management members query error:",
                errorText
            );

            throw new Error(
                "Unable to load management members."
            );
        }

        const members =
            await membersResponse.json();

        // -----------------------------------------
        // RETURN DATA
        // -----------------------------------------

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                director: {
                    userId: director.user_id,
                    fullName: director.full_name
                },
                reports,
                members
            })
        };

    } catch (error) {

        console.error(
            "Management Director reports error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Unable to load management reports."
            })
        };
    }
};