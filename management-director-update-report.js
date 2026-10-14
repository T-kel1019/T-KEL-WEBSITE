exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
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
    const SUPABASE_SECRET_KEY =
        process.env.SUPABASE_SECRET_KEY;

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
        // DIRECTOR AUTHORIZATION
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
        // VERIFY AUTH USER
        // -----------------------------------------

        const userResponse = await fetch(
            `${SUPABASE_URL}/auth/v1/user`,
            {
                method: "GET",
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
        // VERIFY ACTIVE DIRECTOR
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
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
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

        const directors =
            await directorResponse.json();

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
        // READ REQUEST BODY
        // -----------------------------------------

        let body;

        try {
            body = JSON.parse(event.body || "{}");
        } catch (error) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Invalid request."
                })
            };
        }

        const reportId =
            typeof body.reportId === "string"
                ? body.reportId.trim()
                : "";

        const status =
            typeof body.status === "string"
                ? body.status.trim()
                : "";

        const assignedTo =
            typeof body.assignedTo === "string"
                ? body.assignedTo.trim()
                : "";

        const directorResponseText =
            typeof body.directorResponse === "string"
                ? body.directorResponse.trim()
                : "";

        // -----------------------------------------
        // VALIDATE REPORT ID
        // -----------------------------------------

        if (!reportId) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Report ID is required."
                })
            };
        }

        // -----------------------------------------
        // VALIDATE STATUS
        // -----------------------------------------

        const allowedStatuses = [
            "OPEN",
            "REVIEWED",
            "IN_PROGRESS",
            "RESOLVED",
            "CLOSED"
        ];

        if (!allowedStatuses.includes(status)) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Invalid report status."
                })
            };
        }

        // -----------------------------------------
        // VALIDATE RESPONSE LENGTH
        // -----------------------------------------

        if (directorResponseText.length > 10000) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Director response is too long."
                })
            };
        }

        // -----------------------------------------
        // VERIFY REPORT EXISTS
        // -----------------------------------------

        const reportLookupResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_reports` +
                `?id=eq.${encodeURIComponent(reportId)}` +
                `&select=id,report_id,management_id,status,assigned_to`,
                {
                    method: "GET",
                    headers: {
                        "apikey": SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!reportLookupResponse.ok) {
            throw new Error(
                "Unable to find report."
            );
        }

        const reports =
            await reportLookupResponse.json();

        if (!reports.length) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Report not found."
                })
            };
        }

        const existingReport = reports[0];

        // -----------------------------------------
        // VERIFY ASSIGNED MEMBER
        // -----------------------------------------

        let validatedAssignedTo = null;

        if (assignedTo) {

            const memberResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/management_accounts` +
                    `?id=eq.${encodeURIComponent(assignedTo)}` +
                    `&account_status=eq.ACTIVE` +
                    `&select=id,management_id,full_name,assigned_role,department`,
                    {
                        method: "GET",
                        headers: {
                            "apikey":
                                SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        }
                    }
                );

            if (!memberResponse.ok) {
                throw new Error(
                    "Unable to verify assigned member."
                );
            }

            const members =
                await memberResponse.json();

            if (!members.length) {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        error:
                            "Assigned management member is not active."
                    })
                };
            }

            validatedAssignedTo =
                members[0].id;
        }

        // -----------------------------------------
        // PREPARE UPDATE
        // -----------------------------------------

        const updateData = {
            status: status,
            assigned_to: validatedAssignedTo,
            director_response:
                directorResponseText || null,
            updated_at:
                new Date().toISOString()
        };

        if (status === "RESOLVED" ||
            status === "CLOSED") {

            updateData.resolved_at =
                new Date().toISOString();

        } else {

            updateData.resolved_at = null;
        }

        // -----------------------------------------
        // UPDATE REPORT
        // -----------------------------------------

        const updateResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_reports` +
                `?id=eq.${encodeURIComponent(reportId)}`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "apikey":
                            SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`,
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
                "Report update error:",
                errorText
            );

            throw new Error(
                "Unable to update report."
            );
        }

        const updatedReports =
            await updateResponse.json();

        // -----------------------------------------
        // AUDIT LOG
        // -----------------------------------------

        const auditResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_audit_logs`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "apikey":
                            SUPABASE_SECRET_KEY,
                        "Authorization":
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    },
                    body: JSON.stringify({
                        actor_user_id: director.user_id,
                        actor_management_id: null,
                        actor_role:
                            "Management Director",
                        action:
                            "UPDATE_MANAGEMENT_REPORT",
                        target_type:
                            "management_report",
                        target_id:
                            existingReport.report_id,
                        description:
                            `Management Director updated report ${existingReport.report_id}. ` +
                            `Status changed from ${existingReport.status} to ${status}.`
                    })
                }
            );

        if (!auditResponse.ok) {
            console.error(
                "Audit log could not be written."
            );
        }

        // -----------------------------------------
        // RETURN RESULT
        // -----------------------------------------

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            },
            body: JSON.stringify({
                success: true,
                message:
                    "Management report updated successfully.",
                report:
                    updatedReports[0] || null
            })
        };

    } catch (error) {

        console.error(
            "Management Director update error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error:
                    "Unable to update management report."
            })
        };
    }
};