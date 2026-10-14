const crypto = require("crypto");

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    };

    if (event.httpMethod !== "GET") {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }

    try {
        // ---------------------------------------------
        // GET MANAGEMENT SESSION COOKIE
        // ---------------------------------------------

        const cookieHeader = event.headers?.cookie || "";

        const sessionMatch = cookieHeader.match(
            /(?:^|;\s*)t-kel_management_session=([^;]+)/
        );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        // ---------------------------------------------
        // HASH SESSION TOKEN
        // ---------------------------------------------

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        const SUPABASE_URL = process.env.SUPABASE_URL;
        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Supabase environment variables are missing."
            );
        }

        const supabaseHeaders = {
            "apikey": SUPABASE_SECRET_KEY,
            "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`,
            "Content-Type": "application/json"
        };

        // ---------------------------------------------
        // VERIFY SESSION
        // ---------------------------------------------

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(
                new Date().toISOString()
            )}` +
            `&select=id,management_account_id`,
            {
                headers: supabaseHeaders
            }
        );

        if (!sessionResponse.ok) {
            throw new Error(
                "Unable to verify management session."
            );
        }

        const sessions =
            await sessionResponse.json();

        if (!sessions.length) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        // ---------------------------------------------
        // VERIFY LOGGED-IN ACCOUNT
        // ---------------------------------------------

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(
                session.management_account_id
            )}` +
            `&select=id,management_id,full_name,assigned_role,department,account_status`,
            {
                headers: supabaseHeaders
            }
        );

        if (!accountResponse.ok) {
            throw new Error(
                "Unable to load management account."
            );
        }

        const accounts =
            await accountResponse.json();

        if (!accounts.length) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Management account not found."
                })
            };
        }

        const currentAccount = accounts[0];

        if (
            currentAccount.account_status !==
            "ACTIVE"
        ) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account is not active."
                })
            };
        }

        // ---------------------------------------------
        // ONLY PRO 1 AND PRO 2 MAY ACCESS DIRECTORY
        // ---------------------------------------------

        const normalizedRole =
            String(
                currentAccount.assigned_role || ""
            )
                .trim()
                .toLowerCase();

        if (
            normalizedRole !== "pro 1" &&
            normalizedRole !== "pro 2"
        ) {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({
                    success: false,
                    message:
                        "People Directory is available only to PRO 1 and PRO 2."
                })
            };
        }

        // ---------------------------------------------
        // LOAD ACTIVE MANAGEMENT MEMBERS
        // ---------------------------------------------

        const membersResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?account_status=eq.ACTIVE` +
            `&select=id,management_id,full_name,email,phone,assigned_role,department` +
            `&order=full_name.asc`,
            {
                headers: supabaseHeaders
            }
        );

        if (!membersResponse.ok) {
            throw new Error(
                "Unable to load people directory."
            );
        }

        const members =
            await membersResponse.json();

        // ---------------------------------------------
        // REMOVE THE CURRENT PRO FROM RECIPIENT LIST
        // ---------------------------------------------

        const people = members
            .filter(
                member =>
                    member.id !==
                    currentAccount.id
            )
            .map(member => ({
                id: member.id,
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
                    member.department
            }));

        // ---------------------------------------------
        // UPDATE SESSION ACTIVITY
        // ---------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(
                session.id
            )}`,
            {
                method: "PATCH",
                headers: {
                    ...supabaseHeaders,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    last_used_at:
                        new Date().toISOString()
                })
            }
        );

        // ---------------------------------------------
        // RETURN DIRECTORY
        // ---------------------------------------------

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                people,
                count: people.length
            })
        };

    } catch (error) {

        console.error(
            "PRO PEOPLE DIRECTORY ERROR:",
            error
        );

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to load People Directory."
            })
        };
    }
};