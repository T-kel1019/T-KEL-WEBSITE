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
                    error:
                        "Director authentication required."
                })
            };
        }

        const accessToken =
            authorization.substring(7).trim();

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
                    error:
                        "Invalid Director session."
                })
            };
        }

        const user =
            await userResponse.json();

        if (!user || !user.id) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Invalid Director session."
                })
            };
        }

        // -----------------------------------------
        // VERIFY ACTIVE DIRECTOR
        // -----------------------------------------

        const directorResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_directors` +
                `?user_id=eq.${encodeURIComponent(user.id)}` +
                `&active=eq.true` +
                `&select=user_id,full_name,active`,
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

        if (!directorResponse.ok) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Director authorization check failed."
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
                    error:
                        "Director access denied."
                })
            };
        }

        const director = directors[0];

        // -----------------------------------------
        // READ REQUEST
        // -----------------------------------------

        let body;

        try {
            body = JSON.parse(
                event.body || "{}"
            );
        } catch (error) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Invalid request."
                })
            };
        }

        const memberId =
            typeof body.memberId === "string"
                ? body.memberId.trim()
                : "";

        const action =
            typeof body.action === "string"
                ? body.action.trim().toUpperCase()
                : "";

        const removalReason =
            typeof body.removalReason === "string"
                ? body.removalReason.trim()
                : "";

        // -----------------------------------------
        // VALIDATE ACTION
        // -----------------------------------------

        const allowedActions = [
            "SUSPEND",
            "RESTORE",
            "REMOVE"
        ];

        if (!allowedActions.includes(action)) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Invalid member action."
                })
            };
        }

        if (!memberId) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Management member ID is required."
                })
            };
        }

        // -----------------------------------------
        // GET MEMBER
        // -----------------------------------------

        const memberResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(memberId)}` +
                `&select=id,management_id,full_name,email,assigned_role,department,account_status`,
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
                "Unable to find management member."
            );
        }

        const members =
            await memberResponse.json();

        if (!members.length) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Management member not found."
                })
            };
        }

        const member = members[0];

        // -----------------------------------------
        // NEVER ALLOW REMOVED ACCOUNT TO CHANGE
        // -----------------------------------------

        if (
            member.account_status === "REMOVED"
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This management account has already been removed."
                })
            };
        }

        // -----------------------------------------
        // PREPARE ACTION
        // -----------------------------------------

        let newStatus;

        if (action === "SUSPEND") {
            newStatus = "SUSPENDED";
        }

        if (action === "RESTORE") {
            newStatus = "ACTIVE";
        }

        if (action === "REMOVE") {
            newStatus = "REMOVED";
        }

        // -----------------------------------------
        // VALIDATE STATE TRANSITION
        // -----------------------------------------

        if (
            action === "SUSPEND" &&
            member.account_status !== "ACTIVE"
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Only an active account can be suspended."
                })
            };
        }

        if (
            action === "RESTORE" &&
            member.account_status !== "SUSPENDED"
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Only a suspended account can be restored."
                })
            };
        }

        if (
            action === "REMOVE" &&
            ![
                "ACTIVE",
                "SUSPENDED"
            ].includes(member.account_status)
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This account cannot be removed."
                })
            };
        }

        // -----------------------------------------
        // VALIDATE REMOVAL REASON
        // -----------------------------------------

        if (
            action === "REMOVE" &&
            removalReason.length > 2000
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Removal reason is too long."
                })
            };
        }

        // -----------------------------------------
        // UPDATE ACCOUNT
        // -----------------------------------------

        const updateData = {
            account_status: newStatus,
            updated_at:
                new Date().toISOString()
        };

        if (action === "REMOVE") {

            updateData.removed_at =
                new Date().toISOString();

            updateData.removal_reason =
                removalReason || null;

        } else {

            updateData.removed_at = null;

            updateData.removal_reason = null;
        }

        const updateResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(member.id)}`,
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
                    body:
                        JSON.stringify(updateData)
                }
            );

        if (!updateResponse.ok) {

            const errorText =
                await updateResponse.text();

            console.error(
                "Account update error:",
                errorText
            );

            throw new Error(
                "Unable to update management account."
            );
        }

        const updatedMembers =
            await updateResponse.json();

        // -----------------------------------------
        // REVOKE SESSIONS
        // -----------------------------------------
        // Suspension and removal immediately
        // invalidate existing member sessions.

        if (
            action === "SUSPEND" ||
            action === "REMOVE"
        ) {

            const revokeResponse =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/management_sessions` +
                    `?management_account_id=eq.${encodeURIComponent(member.id)}` +
                    `&revoked_at=is.null`,
                    {
                        method: "PATCH",
                        headers: {
                            "Content-Type":
                                "application/json",
                            "apikey":
                                SUPABASE_SECRET_KEY,
                            "Authorization":
                                `Bearer ${SUPABASE_SECRET_KEY}`
                        },
                        body: JSON.stringify({
                            revoked_at:
                                new Date().toISOString()
                        })
                    }
                );

            if (!revokeResponse.ok) {
                console.error(
                    "Session revocation failed."
                );
            }
        }

        // -----------------------------------------
        // AUDIT LOG
        // -----------------------------------------

        const auditDescription =
            action === "REMOVE"
                ? `Management Director removed management account ${member.management_id}.` +
                  (
                      removalReason
                          ? ` Reason: ${removalReason}`
                          : ""
                  )
                : `Management Director changed management account ${member.management_id} ` +
                  `from ${member.account_status} to ${newStatus}.`;

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
                        actor_user_id:
                            director.user_id,
                        actor_management_id:
                            null,
                        actor_role:
                            "Management Director",
                        action:
                            `MANAGEMENT_ACCOUNT_${action}`,
                        target_type:
                            "management_account",
                        target_id:
                            member.management_id,
                        description:
                            auditDescription
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
                "Content-Type":
                    "application/json",
                "Cache-Control":
                    "no-store"
            },
            body: JSON.stringify({
                success: true,
                message:
                    `Management account ${action.toLowerCase()} successful.`,
                member:
                    updatedMembers[0] || null
            })
        };

    } catch (error) {

        console.error(
            "Management member action error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                error:
                    "Unable to update management account."
            })
        };
    }
};