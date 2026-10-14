const crypto = require("crypto");

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

    try {

        const SUPABASE_URL = process.env.SUPABASE_URL;
        const SUPABASE_SECRET_KEY =
            process.env.SUPABASE_SECRET_KEY;

        if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
            throw new Error(
                "Server configuration is incomplete."
            );
        }

        /* --------------------------------
           Read Management session cookie
        -------------------------------- */

        const cookieHeader =
            event.headers.cookie ||
            event.headers.Cookie ||
            "";

        const cookieMatch =
            cookieHeader.match(
                /(?:^|;\s*)t-kel_management_session=([^;]+)/
            );

        if (!cookieMatch) {
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

        const sessionToken =
            decodeURIComponent(cookieMatch[1]);

        if (!sessionToken) {
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

        /* --------------------------------
           Hash session token
        -------------------------------- */

        const tokenHash = crypto
            .createHash("sha256")
            .update(sessionToken)
            .digest("hex");

        /* --------------------------------
           Find valid session
        -------------------------------- */

        const sessionResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_sessions` +
            `?token_hash=eq.${encodeURIComponent(tokenHash)}` +
            `&revoked_at=is.null` +
            `&expires_at=gt.${encodeURIComponent(new Date().toISOString())}` +
            `&select=id,management_account_id,expires_at`,
            {
                method: "GET",
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

        if (!sessions.length) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Invalid or expired session."
                })
            };
        }

        const session = sessions[0];

        /* --------------------------------
           Get Management account
        -------------------------------- */

        const accountResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(
                session.management_account_id
            )}` +
            `&select=id,management_id,full_name,password_hash,account_status`,
            {
                method: "GET",
                headers: {
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`
                }
            }
        );

        if (!accountResponse.ok) {
            throw new Error(
                "Unable to retrieve management account."
            );
        }

        const accounts =
            await accountResponse.json();

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

        if (account.account_status !== "ACTIVE") {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "This management account is not active."
                })
            };
        }

        /* --------------------------------
           Read request body
        -------------------------------- */

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

        const currentPassword =
            typeof body.currentPassword === "string"
                ? body.currentPassword
                : "";

        const newPassword =
            typeof body.newPassword === "string"
                ? body.newPassword
                : "";

        /* --------------------------------
           Validate passwords
        -------------------------------- */

        if (!currentPassword || !newPassword) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Current password and new password are required."
                })
            };
        }

        if (newPassword.length < 8) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "New password must be at least 8 characters."
                })
            };
        }

        if (newPassword.length > 200) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "New password is too long."
                })
            };
        }

        if (currentPassword === newPassword) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "New password must be different from the current password."
                })
            };
        }

        /* --------------------------------
           Verify current password
        -------------------------------- */

        const storedPassword =
            account.password_hash || "";

        const storedParts =
            storedPassword.split(":");

        if (
            storedParts.length !== 3 ||
            storedParts[0] !== "scrypt"
        ) {
            throw new Error(
                "Invalid stored password format."
            );
        }

        const salt = storedParts[1];
        const storedKeyHex = storedParts[2];

        const storedKey =
            Buffer.from(storedKeyHex, "hex");

        const derivedCurrentKey =
            await new Promise(
                (resolve, reject) => {
                    crypto.scrypt(
                        currentPassword,
                        salt,
                        storedKey.length,
                        {
                            N: 16384,
                            r: 8,
                            p: 1
                        },
                        (error, derivedKey) => {
                            if (error) {
                                reject(error);
                            } else {
                                resolve(derivedKey);
                            }
                        }
                    );
                }
            );

        if (
            storedKey.length !==
            derivedCurrentKey.length
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Current password is incorrect."
                })
            };
        }

        const passwordMatches =
            crypto.timingSafeEqual(
                storedKey,
                derivedCurrentKey
            );

        if (!passwordMatches) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Current password is incorrect."
                })
            };
        }

        /* --------------------------------
           Create new password hash
        -------------------------------- */

        const newSalt =
            crypto.randomBytes(16).toString("hex");

        const newDerivedKey =
            await new Promise(
                (resolve, reject) => {
                    crypto.scrypt(
                        newPassword,
                        newSalt,
                        64,
                        {
                            N: 16384,
                            r: 8,
                            p: 1
                        },
                        (error, derivedKey) => {
                            if (error) {
                                reject(error);
                            } else {
                                resolve(derivedKey);
                            }
                        }
                    );
                }
            );

        const newPasswordHash =
            `scrypt:${newSalt}:${newDerivedKey.toString("hex")}`;

        /* --------------------------------
           Update password
        -------------------------------- */

        const updateResponse = await fetch(
            `${SUPABASE_URL}/rest/v1/management_accounts` +
            `?id=eq.${encodeURIComponent(account.id)}`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type":
                        "application/json",
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    password_hash:
                        newPasswordHash,
                    updated_at:
                        new Date().toISOString()
                })
            }
        );

        if (!updateResponse.ok) {
            throw new Error(
                "Unable to update password."
            );
        }

        /* --------------------------------
           Revoke all existing sessions
           The member must log in again.
        -------------------------------- */

        const revokeResponse = await fetch(
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
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    revoked_at:
                        new Date().toISOString()
                })
            }
        );

        if (!revokeResponse.ok) {
            throw new Error(
                "Password changed, but existing sessions could not be revoked."
            );
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
                    "apikey": SUPABASE_SECRET_KEY,
                    "Authorization":
                        `Bearer ${SUPABASE_SECRET_KEY}`,
                    "Prefer": "return=minimal"
                },
                body: JSON.stringify({
                    actor_user_id: null,
                    actor_management_id:
                        account.management_id,
                    actor_role:
                        "Management Member",
                    action:
                        "CHANGE_MANAGEMENT_PASSWORD",
                    target_type:
                        "management_account",
                    target_id:
                        account.management_id,
                    description:
                        "Management member changed their password."
                })
            }
        );

        /* --------------------------------
           Clear current session cookie
        -------------------------------- */

        return {
            statusCode: 200,
            headers: {
                "Content-Type":
                    "application/json",
                "Set-Cookie":
                    "t-kel_management_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
                "Cache-Control":
                    "no-store"
            },
            body: JSON.stringify({
                success: true,
                message:
                    "Password changed successfully. Please log in again."
            })
        };

    } catch (error) {

        console.error(
            "Management password change error:",
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
                    "Unable to change password."
            })
        };
    }
};