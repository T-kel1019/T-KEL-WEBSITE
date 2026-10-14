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
        // GET MANAGEMENT SESSION COOKIE
        // -----------------------------------------

        const cookieHeader = event.headers.cookie || "";

        const sessionMatch = cookieHeader.match(
            /(?:^|;\s*)t-kel_management_session=([^;]+)/
        );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        // -----------------------------------------
        // HASH SESSION TOKEN
        // -----------------------------------------

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        // -----------------------------------------
        // FIND VALID SESSION
        // -----------------------------------------

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(new Date().toISOString())}` +
            `&select=id,management_account_id`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!sessionResponse.ok) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Invalid management session."
                })
            };
        }

        const sessions = await sessionResponse.json();

        if (!sessions.length) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Management session expired."
                })
            };
        }

        const session = sessions[0];

        // -----------------------------------------
        // GET MANAGEMENT ACCOUNT
        // -----------------------------------------

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(session.management_account_id)}` +
            `&select=id,management_id,full_name,assigned_role,department,account_status`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!accountResponse.ok) {
            throw new Error("Unable to verify management account.");
        }

        const accounts = await accountResponse.json();

        if (!accounts.length) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Management account not found."
                })
            };
        }

        const account = accounts[0];

        // -----------------------------------------
        // CHECK ACCOUNT STATUS
        // -----------------------------------------

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Management account is not active."
                })
            };
        }

        // -----------------------------------------
        // GET MEMBER'S REPORTS
        // -----------------------------------------

        const reportsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_reports` +
            `?management_account_id=eq.${encodeURIComponent(account.id)}` +
            `&select=id,report_id,management_id,staff_name,assigned_role,department,report_type,description,status,assigned_to,director_response,created_at,updated_at,resolved_at` +
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
            const errorText = await reportsResponse.text();

            console.error(
                "Reports query error:",
                errorText
            );

            throw new Error("Unable to load reports.");
        }

        const reports = await reportsResponse.json();

        // -----------------------------------------
        // UPDATE SESSION LAST USED
        // -----------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`
                },
                body: JSON.stringify({
                    last_used_at: new Date().toISOString()
                })
            }
        );

        // -----------------------------------------
        // RETURN REPORTS
        // -----------------------------------------

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                reports
            })
        };

    } catch (error) {

        console.error(
            "Management reports error:",
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