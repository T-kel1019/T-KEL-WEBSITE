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

        // --------------------------------------------------
        // 1. VERIFY MANAGEMENT SESSION
        // --------------------------------------------------

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(new Date().toISOString())}` +
            `&select=id,management_account_id,expires_at`,
            {
                headers: supabaseHeaders
            }
        );

        if (!sessionResponse.ok) {
            throw new Error(
                "Unable to verify management session."
            );
        }

        const sessions = await sessionResponse.json();

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

        // --------------------------------------------------
        // 2. LOAD MANAGEMENT ACCOUNT
        // --------------------------------------------------

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(session.management_account_id)}` +
            `&select=id,management_id,full_name,email,phone,assigned_role,department,account_status,created_at,last_login_at`,
            {
                headers: supabaseHeaders
            }
        );

        if (!accountResponse.ok) {
            throw new Error(
                "Unable to load management account."
            );
        }

        const accounts = await accountResponse.json();

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

        const account = accounts[0];

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Management account is not active."
                })
            };
        }

        const normalizedRole =
            String(account.assigned_role || "")
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
                        "This dashboard data is available only to PRO 1 and PRO 2."
                })
            };
        }

        // --------------------------------------------------
        // 3. UPDATE SESSION ACTIVITY
        // --------------------------------------------------

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    ...supabaseHeaders,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    last_used_at: new Date().toISOString()
                })
            }
        );

        // --------------------------------------------------
        // 4. LOAD DIRECTOR INSTRUCTIONS
        // --------------------------------------------------

        const instructionsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_director_instructions` +
            `?assigned_pro_account_id=eq.${encodeURIComponent(account.id)}` +
            `&select=id,instruction_id,title,instruction_text,priority,status,director_note,created_at,updated_at` +
            `&order=created_at.desc`,
            {
                headers: supabaseHeaders
            }
        );

        if (!instructionsResponse.ok) {
            throw new Error(
                "Unable to load director instructions."
            );
        }

        const instructions =
            await instructionsResponse.json();

        // --------------------------------------------------
        // 5. LOAD COMMUNICATIONS SENT BY THIS PRO
        // --------------------------------------------------

        const communicationsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_communications` +
            `?pro_account_id=eq.${encodeURIComponent(account.id)}` +
            `&select=id,communication_id,subject,message,priority,status,director_instruction_id,created_at,updated_at` +
            `&order=created_at.desc`,
            {
                headers: supabaseHeaders
            }
        );

        if (!communicationsResponse.ok) {
            throw new Error(
                "Unable to load PRO communications."
            );
        }

        const communications =
            await communicationsResponse.json();

        // --------------------------------------------------
        // 6. LOAD RECIPIENTS FOR THOSE COMMUNICATIONS
        // --------------------------------------------------

        let communicationRecipients = [];

        if (communications.length) {
            const communicationIds =
                communications
                    .map(item => item.id)
                    .filter(Boolean);

            if (communicationIds.length) {
                const idsFilter =
                    communicationIds.join(",");

                const recipientsResponse = await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communication_recipients` +
                    `?communication_id=in.(${encodeURIComponent(idsFilter)})` +
                    `&select=id,communication_id,recipient_management_account_id,recipient_management_id,recipient_name,recipient_role,delivery_status,acknowledged_at,created_at` +
                    `&order=created_at.desc`,
                    {
                        headers: supabaseHeaders
                    }
                );

                if (!recipientsResponse.ok) {
                    throw new Error(
                        "Unable to load communication recipients."
                    );
                }

                communicationRecipients =
                    await recipientsResponse.json();
            }
        }

        // Attach recipients to each communication
        const communicationsWithRecipients =
            communications.map(communication => ({
                ...communication,
                recipients:
                    communicationRecipients.filter(
                        recipient =>
                            recipient.communication_id ===
                            communication.id
                    )
            }));

        // --------------------------------------------------
        // 7. LOAD REPORTS SENT TO DIRECTOR
        // --------------------------------------------------

        const reportsResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/pro_director_reports` +
            `?pro_account_id=eq.${encodeURIComponent(account.id)}` +
            `&select=id,report_id,director_instruction_id,communication_id,report_title,report_text,outcome,follow_up_required,status,director_response,created_at,updated_at` +
            `&order=created_at.desc`,
            {
                headers: supabaseHeaders
            }
        );

        if (!reportsResponse.ok) {
            throw new Error(
                "Unable to load PRO director reports."
            );
        }

        const reports =
            await reportsResponse.json();

        // --------------------------------------------------
        // 8. BUILD FOLLOW-UP LIST
        // --------------------------------------------------

        const followUps = reports.filter(
            report =>
                report.follow_up_required === true ||
                report.status === "FOLLOW_UP"
        );

        // --------------------------------------------------
        // 9. RETURN DASHBOARD DATA
        // --------------------------------------------------

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,

                account: {
                    id: account.id,
                    managementId: account.management_id,
                    fullName: account.full_name,
                    email: account.email,
                    phone: account.phone,
                    assignedRole: account.assigned_role,
                    department: account.department,
                    accountStatus: account.account_status,
                    createdAt: account.created_at,
                    lastLoginAt: account.last_login_at
                },

                instructions,

                communications:
                    communicationsWithRecipients,

                reports,

                followUps,

                summary: {
                    instructions: instructions.length,
                    communications:
                        communications.length,
                    reports: reports.length,
                    followUps: followUps.length
                }
            })
        };

    } catch (error) {

        console.error(
            "PRO DASHBOARD DATA ERROR:",
            error
        );

        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to load PRO dashboard data."
            })
        };
    }
};