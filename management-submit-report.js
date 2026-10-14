const crypto = require("crypto");

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function getCookie(event, name) {

    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {

        const parts =
            cookie.trim().split("=");

        const key = parts.shift();

        if (key === name) {
            return decodeURIComponent(
                parts.join("=")
            );
        }
    }

    return null;
}

function generateReportId() {

    const randomPart =
        crypto
            .randomBytes(5)
            .toString("hex")
            .toUpperCase();

    return `TKEL-RPT-${randomPart}`;
}


exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {

        return {
            statusCode: 405,
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


        /* --------------------------------
           VERIFY MANAGEMENT SESSION
        -------------------------------- */

        const sessionToken =
            getCookie(
                event,
                "t-kel_management_session"
            );


        if (!sessionToken) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management login required."
                })
            };
        }


        const tokenHash =
            hashToken(sessionToken);


        const sessionResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_sessions` +
                `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
                `&select=id,management_account_id,expires_at,revoked_at`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
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
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Management session."
                })
            };
        }


        const session =
            sessions[0];


        if (
            session.revoked_at ||
            new Date(session.expires_at).getTime()
                <= Date.now()
        ) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session has expired or been revoked."
                })
            };
        }


        /* --------------------------------
           GET MANAGEMENT ACCOUNT
        -------------------------------- */

        const accountResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(session.management_account_id)}` +
                `&select=id,management_id,full_name,assigned_role,department,account_status`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,
                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!accountResponse.ok) {
            throw new Error(
                "Unable to retrieve Management account."
            );
        }


        const accounts =
            await accountResponse.json();


        if (!accounts.length) {

            return {
                statusCode: 401,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account not found."
                })
            };
        }


        const account =
            accounts[0];


        if (
            account.account_status !== "ACTIVE"
        ) {

            return {
                statusCode: 403,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Your Management account is not active."
                })
            };
        }


        /* --------------------------------
           READ REPORT
        -------------------------------- */

        const {
            reportType,
            description
        } = JSON.parse(event.body || "{}");


        if (!reportType || !description) {

            return {
                statusCode: 400,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report type and description are required."
                })
            };
        }


        const cleanReportType =
            String(reportType)
                .trim()
                .slice(0, 100);


        const cleanDescription =
            String(description)
                .trim()
                .slice(0, 10000);


        if (
            !cleanReportType ||
            !cleanDescription
        ) {

            return {
                statusCode: 400,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report information cannot be empty."
                })
            };
        }


        /* --------------------------------
           GENERATE REPORT ID
        -------------------------------- */

        let reportId;
        let inserted = false;

        for (let attempt = 0; attempt < 5; attempt++) {

            reportId =
                generateReportId();


            const reportResponse =
                await fetch(
                    `${supabaseUrl}/rest/v1/management_reports`,
                    {
                        method: "POST",

                        headers: {
                            apikey: supabaseKey,
                            Authorization:
                                `Bearer ${supabaseKey}`,
                            "Content-Type":
                                "application/json",
                            Prefer:
                                "return=representation"
                        },

                        body: JSON.stringify({

                            report_id:
                                reportId,

                            management_account_id:
                                account.id,

                            management_id:
                                account.management_id,

                            staff_name:
                                account.full_name,

                            assigned_role:
                                account.assigned_role,

                            department:
                                account.department,

                            report_type:
                                cleanReportType,

                            description:
                                cleanDescription,

                            status:
                                "OPEN"
                        })
                    }
                );


            if (reportResponse.ok) {

                inserted = true;
                break;
            }


            const errorText =
                await reportResponse.text();


            /*
             * If the failure was not caused by
             * a duplicate report ID, stop.
             */

            if (
                !errorText
                    .toLowerCase()
                    .includes("duplicate")
            ) {

                console.error(
                    "Report insertion error:",
                    errorText
                );

                throw new Error(
                    "Failed to submit management report."
                );
            }
        }


        if (!inserted) {

            throw new Error(
                "Unable to generate a unique Report ID."
            );
        }


        /* --------------------------------
           AUDIT LOG
        -------------------------------- */

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

                    actor_management_id:
                        account.management_id,

                    actor_role:
                        account.assigned_role,

                    action:
                        "CREATE_REPORT",

                    target_type:
                        "management_report",

                    target_id:
                        reportId,

                    description:
                        `Management member submitted report ${reportId}.`
                })
            }
        );


        return {

            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                success: true,

                message:
                    "Report submitted successfully.",

                reportId:
                    reportId
            })
        };


    } catch (error) {

        console.error(
            "Management report submission error:",
            error
        );


        return {

            statusCode: 500,

            body: JSON.stringify({

                success: false,

                message:
                    "An internal server error occurred."
            })
        };
    }
};