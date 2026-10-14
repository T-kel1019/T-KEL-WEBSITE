const crypto = require("crypto");

function getBearerToken(event) {
    const authorization =
        event.headers.authorization ||
        event.headers.Authorization ||
        "";

    if (!authorization.startsWith("Bearer ")) {
        return null;
    }

    return authorization.slice(7).trim();
}

exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                success: false,
                message: "Method not allowed."
            })
        };
    }

    try {

        const SUPABASE_URL =
            process.env.SUPABASE_URL;

        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Supabase environment variables are missing."
            );
        }

        /* --------------------------------
           Get Director Supabase Auth token
        -------------------------------- */

        const accessToken =
            getBearerToken(event);

        if (!accessToken) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director authorization required."
                })
            };
        }

        /* --------------------------------
           Verify Supabase Auth user
        -------------------------------- */

        const userResponse =
            await fetch(
                `${SUPABASE_URL}/auth/v1/user`,
                {
                    method: "GET",
                    headers: {
                        apikey:
                            SUPABASE_SECRET_KEY,
                        Authorization:
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
                    success: false,
                    message:
                        "Invalid Director authorization."
                })
            };
        }

        const directorUser =
            await userResponse.json();

        if (!directorUser || !directorUser.id) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director authorization required."
                })
            };
        }

        /* --------------------------------
           Verify active Director
        -------------------------------- */

        const directorResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_directors` +
                `?user_id=eq.${encodeURIComponent(
                    directorUser.id
                )}` +
                `&active=eq.true` +
                `&select=id,user_id,active`,
                {
                    method: "GET",
                    headers: {
                        apikey:
                            SUPABASE_SECRET_KEY,
                        Authorization:
                            `Bearer ${SUPABASE_SECRET_KEY}`
                    }
                }
            );

        if (!directorResponse.ok) {
            throw new Error(
                "Unable to verify Director account."
            );
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
                    success: false,
                    message:
                        "Only an active Management Director can remove a Management member."
                })
            };
        }

        /* --------------------------------
           Read request body
        -------------------------------- */

        let body;

        try {
            body =
                JSON.parse(event.body || "{}");
        } catch (error) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid request."
                })
            };
        }

        const managementAccountId =
            typeof body.managementAccountId === "string"
                ? body.managementAccountId.trim()
                : "";

        const removalReason =
            typeof body.removalReason === "string"
                ? body.removalReason.trim()
                : "";

        if (!managementAccountId) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account ID is required."
                })
            };
        }

        if (!removalReason) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "A removal reason is required."
                })
            };
        }

        if (removalReason.length > 1000) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Removal reason is too long."
                })
            };
        }

        /* --------------------------------
           Find Management account
        -------------------------------- */

        const accountResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(
                    managementAccountId
                )}` +
                `&select=id,management_id,full_name,email,assigned_role,department,account_status`,
                {
                    method: "GET",
                    headers: {
                        apikey:
                            SUPABASE_SECRET_KEY,
                        Authorization:
                            `Bearer ${SUPABASE_SECRET_KEY}`
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
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management account not found."
                })
            };
        }

        const account =
            accounts[0];

        /* --------------------------------
           Prevent repeated removal
        -------------------------------- */

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        `This Management account is already ${String(
                            account.account_status || "inactive"
                        ).toLowerCase()}.`
                })
            };
        }

        /* --------------------------------
           Update account status
           DO NOT DELETE THE ACCOUNT
        -------------------------------- */

        const removalTime =
            new Date().toISOString();

        const updateResponse =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(
                    account.id
                )}`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type":
                            "application/json",
                        apikey:
                            SUPABASE_SECRET_KEY,
                        Authorization:
                            `Bearer ${SUPABASE_SECRET_KEY}`,
                        Prefer:
                            "return=minimal"
                    },
                    body: JSON.stringify({
                        account_status:
                            "REMOVED",
                        removed_at:
                            removalTime,
                        removed_by:
                            directorUser.id,
                        removal_reason:
                            removalReason,
                        updated_at:
                            removalTime
                    })
                }
            );

        if (!updateResponse.ok) {
            throw new Error(
                "Unable to remove Management member."
            );
        }

        /* --------------------------------
           Revoke Management sessions
        -------------------------------- */

        const revokeManagementSessions =
            await fetch(
                `${SUPABASE_URL}/rest/v1/management_sessions` +
                `?management_account_id=eq.${encodeURIComponent(
                    account.id
                )}` +
                `&revoked_at=is.null`,
                {
                    method: "PATCH",
                    headers: {
                        "Content-Type":
                            "application/json",
                        apikey:
                            SUPABASE_SECRET_KEY,
                        Authorization:
                            `Bearer ${SUPABASE_SECRET_KEY}`,
                        Prefer:
                            "return=minimal"
                    },
                    body: JSON.stringify({
                        revoked_at:
                            removalTime
                    })
                }
            );

        if (!revokeManagementSessions.ok) {
            throw new Error(
                "Member removed, but Management sessions could not be revoked."
            );
        }

        /* --------------------------------
           Revoke Media Manager sessions
           if this account was Media Manager
        -------------------------------- */

        if (
            String(account.assigned_role || "")
                .toLowerCase()
                === "media manager"
        ) {

            const revokeMediaSessions =
                await fetch(
                    `${SUPABASE_URL}/rest/v1/media_manager_sessions` +
                    `?management_account_id=eq.${encodeURIComponent(
                        account.id
                    )}` +
                    `&revoked_at=is.null`,
                    {
                        method: "PATCH",
                        headers: {
                            "Content-Type":
                                "application/json",
                            apikey:
                                SUPABASE_SECRET_KEY,
                            Authorization:
                                `Bearer ${SUPABASE_SECRET_KEY}`,
                            Prefer:
                                "return=minimal"
                        },
                        body: JSON.stringify({
                            revoked_at:
                                removalTime
                        })
                    }
                );

            if (!revokeMediaSessions.ok) {
                throw new Error(
                    "Member removed, but Media Manager sessions could not be revoked."
                );
            }
        }

        /* --------------------------------
           Audit log
        -------------------------------- */

        await fetch(
            `${SUPABASE_URL}/rest/v1/management_audit_logs`,
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",
                    apikey:
                        SUPABASE_SECRET_KEY,
                    Authorization:
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    Prefer:
                        "return=minimal"
                },
                body: JSON.stringify({
                    actor_user_id:
                        directorUser.id,

                    actor_management_id:
                        null,

                    actor_role:
                        "Management Director",

                    action:
                        "REMOVE_MANAGEMENT_MEMBER",

                    target_type:
                        "management_account",

                    target_id:
                        account.management_id,

                    description:
                        `Management member ${account.full_name} (${account.management_id}) was removed from the ${account.assigned_role} role. Reason: ${removalReason}`
                })
            }
        );

        /* --------------------------------
           Success
        -------------------------------- */

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
                    "Management member removed successfully. Their role workspace and data were preserved.",
                removedMember: {
                    managementId:
                        account.management_id,
                    fullName:
                        account.full_name,
                    assignedRole:
                        account.assigned_role,
                    department:
                        account.department,
                    removedAt:
                        removalTime
                }
            })
        };

    } catch (error) {

        console.error(
            "Management member removal error:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: false,
                message:
                    "Unable to remove Management member."
            })
        };
    }
};