const crypto = require("crypto");

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

        const cookies = event.headers.cookie || "";

        const sessionMatch =
            cookies.match(
                /t-kel_management_session=([^;]+)/
            );

        if (!sessionMatch) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session required."
                })
            };
        }

        const sessionToken = sessionMatch[1];

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        /*
         * Verify session
         */

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,management_account_id,expires_at,revoked_at`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
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

        if (
            !sessions.length ||
            sessions[0].revoked_at ||
            new Date(sessions[0].expires_at) <= new Date()
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        /*
         * Load logged-in management account
         */

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts?id=eq.${encodeURIComponent(session.management_account_id)}&select=id,management_id,full_name,assigned_role,department,account_status`,
            {
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
                }
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
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account not found."
                })
            };
        }

        const account = accounts[0];

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account is not active."
                })
            };
        }

        /*
         * Only PRO 1 and PRO 2 can submit PRO reports.
         */

        if (
            account.assigned_role !== "PRO 1" &&
            account.assigned_role !== "PRO 2"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "PRO reporting access is restricted."
                })
            };
        }

        const body =
            JSON.parse(event.body || "{}");

        const {
            directorInstructionId,
            communicationId,
            reportTitle,
            reportText,
            outcome,
            followUpRequired
        } = body;

        /*
         * Validate report title
         */

        if (
            typeof reportTitle !== "string" ||
            !reportTitle.trim()
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report title is required."
                })
            };
        }

        /*
         * Validate report text
         */

        if (
            typeof reportText !== "string" ||
            !reportText.trim()
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report details are required."
                })
            };
        }

        /*
         * Prevent excessively large submissions.
         */

        if (reportTitle.trim().length > 300) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report title is too long."
                })
            };
        }

        if (reportText.trim().length > 10000) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Report details are too long."
                })
            };
        }

        /*
         * Validate optional follow-up flag.
         */

        const requiresFollowUp =
            followUpRequired === true;

        /*
         * If a Director instruction was supplied,
         * verify that this PRO was actually assigned
         * that instruction.
         */

        if (directorInstructionId) {

            const instructionResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_director_instructions?id=eq.${encodeURIComponent(directorInstructionId)}&assigned_pro_account_id=eq.${encodeURIComponent(account.id)}&select=id,status`,
                    {
                        headers: {
                            "apikey":
                                SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        }
                    }
                );

            if (!instructionResponse.ok) {
                throw new Error(
                    "Unable to verify Director instruction."
                );
            }

            const instructions =
                await instructionResponse.json();

            if (!instructions.length) {
                return {
                    statusCode: 403,
                    headers: {
                        "Cache-Control": "no-store"
                    },
                    body: JSON.stringify({
                        success: false,
                        message:
                            "You are not authorized to report against this Director instruction."
                    })
                };
            }

            if (
                instructions[0].status ===
                "CANCELLED"
            ) {
                return {
                    statusCode: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    },
                    body: JSON.stringify({
                        success: false,
                        message:
                            "This Director instruction has been cancelled."
                    })
                };
            }
        }

        /*
         * If a communication was supplied,
         * verify that the communication belongs
         * to this PRO.
         */

        if (communicationId) {

            const communicationResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/pro_communications?id=eq.${encodeURIComponent(communicationId)}&pro_account_id=eq.${encodeURIComponent(account.id)}&select=id`,
                    {
                        headers: {
                            "apikey":
                                SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        }
                    }
                );

            if (!communicationResponse.ok) {
                throw new Error(
                    "Unable to verify communication."
                );
            }

            const communications =
                await communicationResponse.json();

            if (!communications.length) {
                return {
                    statusCode: 403,
                    headers: {
                        "Cache-Control": "no-store"
                    },
                    body: JSON.stringify({
                        success: false,
                        message:
                            "You are not authorized to report against this communication."
                    })
                };
            }
        }

        /*
         * Generate report ID.
         */

        const randomPart =
            crypto
                .randomBytes(5)
                .toString("hex")
                .toUpperCase();

        const reportId =
            "TKEL-PRO-RPT-" + randomPart;

        /*
         * Insert Director report.
         */

        const reportResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/pro_director_reports`,
                {
                    method: "POST",
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`,
                        "Content-Type":
                            "application/json",
                        "Prefer":
                            "return=representation"
                    },
                    body: JSON.stringify({
                        report_id: reportId,
                        pro_account_id: account.id,
                        pro_management_id:
                            account.management_id,
                        pro_name:
                            account.full_name,
                        pro_role:
                            account.assigned_role,
                        director_instruction_id:
                            directorInstructionId ||
                            null,
                        communication_id:
                            communicationId ||
                            null,
                        report_title:
                            reportTitle.trim(),
                        report_text:
                            reportText.trim(),
                        outcome:
                            typeof outcome === "string" &&
                            outcome.trim()
                                ? outcome.trim()
                                : null,
                        follow_up_required:
                            requiresFollowUp,
                        status:
                            requiresFollowUp
                                ? "FOLLOW_UP"
                                : "SUBMITTED"
                    })
                }
            );

        if (!reportResponse.ok) {
            const errorText =
                await reportResponse.text();

            console.error(
                "PRO report insert failed:",
                errorText
            );

            throw new Error(
                "Unable to submit Director report."
            );
        }

        const reports =
            await reportResponse.json();

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
                    actor_user_id: null,
                    actor_management_id:
                        account.management_id,
                    actor_role:
                        account.assigned_role,
                    action:
                        "SUBMIT_PRO_DIRECTOR_REPORT",
                    target_type:
                        "PRO_DIRECTOR_REPORT",
                    target_id:
                        reportId,
                    description:
                        `PRO ${account.management_id} submitted a report to the Director.`
                })
            }
        );

        /*
         * Update session activity.
         */

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions?id=eq.${encodeURIComponent(session.id)}`,
            {
                method: "PATCH",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    last_used_at:
                        new Date().toISOString()
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
                    "Report submitted to the Director successfully.",
                report: reports[0]
            })
        };

    } catch (error) {

        console.error(
            "pro-director-report error:",
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
                    "Unable to submit Director report."
            })
        };
    }
};