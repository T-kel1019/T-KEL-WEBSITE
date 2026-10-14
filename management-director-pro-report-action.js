exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
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
         * Verify Supabase user
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
         * Confirm active Director
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

        const director = directors[0];

        /*
         * Read request
         */

        const body =
            JSON.parse(event.body || "{}");

        const {
            reportId,
            status,
            directorResponse: responseText
        } = body;

        /*
         * Validate report ID
         */

        if (
            typeof reportId !== "string" ||
            !reportId.trim()
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report ID is required."
                })
            };
        }

        /*
         * Allowed Director statuses
         */

        const allowedStatuses = [
            "REVIEWED",
            "FOLLOW_UP",
            "CLOSED"
        ];

        if (!allowedStatuses.includes(status)) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid report status."
                })
            };
        }

        /*
         * Validate Director response
         */

        if (
            responseText !== undefined &&
            responseText !== null &&
            typeof responseText !== "string"
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director response must be text."
                })
            };
        }

        if (
            typeof responseText === "string" &&
            responseText.length > 10000
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director response is too long."
                })
            };
        }

        /*
         * Find the PRO report.
         */

        const reportLookupResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_director_reports?report_id=eq.${encodeURIComponent(reportId.trim())}&select=id,report_id,pro_management_id,pro_name,pro_role,status`,
                {
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!reportLookupResponse.ok) {
            throw new Error(
                "Unable to find PRO report."
            );
        }

        const reports =
            await reportLookupResponse.json();

        if (!reports.length) {
            return {
                statusCode: 404,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "PRO report not found."
                })
            };
        }

        const report = reports[0];

        /*
         * Confirm the report actually belongs
         * to PRO 1 or PRO 2.
         */

        if (
            report.pro_role !== "PRO 1" &&
            report.pro_role !== "PRO 2"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "This report is not a valid PRO report."
                })
            };
        }

        /*
         * Update report.
         */

        const updateData = {
            status: status,
            director_response:
                typeof responseText === "string"
                    ? responseText.trim() || null
                    : null,
            updated_at:
                new Date().toISOString()
        };

        const updateResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_director_reports?id=eq.${encodeURIComponent(report.id)}`,
                {
                    method: "PATCH",
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`,
                        "Content-Type":
                            "application/json",
                        "Prefer":
                            "return=representation"
                    },
                    body: JSON.stringify(updateData)
                }
            );

        if (!updateResponse.ok) {
            const errorText =
                await updateResponse.text();

            console.error(
                "PRO report update failed:",
                errorText
            );

            throw new Error(
                "Unable to update PRO report."
            );
        }

        const updatedReports =
            await updateResponse.json();

        /*
         * Audit log
         */

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    actor_user_id: user.id,
                    actor_management_id: null,
                    actor_role:
                        "Management Director",
                    action:
                        "UPDATE_PRO_DIRECTOR_REPORT",
                    target_type:
                        "PRO_DIRECTOR_REPORT",
                    target_id:
                        report.report_id,
                    description:
                        `Director updated PRO report ${report.report_id} to ${status}.`
                })
            }
        );

        return {
            statusCode: 200,
            headers: {
                "Cache-Control": "no-store",
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                message:
                    "PRO report updated successfully.",
                report:
                    updatedReports[0]
            })
        };

    } catch (error) {

        console.error(
            "management-director-pro-report-action error:",
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
                    "Unable to update PRO report."
            })
        };
    }
};