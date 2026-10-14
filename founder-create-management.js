const crypto = require("crypto");

function getCookie(event, name) {
    const cookieHeader =
        event.headers.cookie ||
        event.headers.Cookie ||
        "";

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const parts = cookie.trim().split("=");

        const key = parts.shift();

        if (key === name) {
            return decodeURIComponent(parts.join("="));
        }
    }

    return null;
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function generateManagementId() {

    const characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let id = "TK";

    for (let i = 0; i < 6; i++) {

        id += characters.charAt(
            Math.floor(
                Math.random() * characters.length
            )
        );
    }

    return id;
}

function generatePassword(length = 10) {

    const characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    let password = "";

    for (let i = 0; i < length; i++) {

        password += characters.charAt(
            Math.floor(
                Math.random() * characters.length
            )
        );
    }

    return password;
}

function hashPassword(password) {

    const salt =
        crypto.randomBytes(16).toString("hex");

    const derivedKey =
        crypto.scryptSync(
            password,
            salt,
            64
        ).toString("hex");

    return `scrypt:${salt}:${derivedKey}`;
}


exports.handler = async (event) => {

    if (event.httpMethod !== "POST") {

        return {
            statusCode: 405,

            headers: {
                "Content-Type":
                    "application/json"
            },

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


        /* =====================================
           VERIFY FOUNDER SESSION
        ===================================== */

        const sessionToken =
            getCookie(
                event,
                "t-kel_management_session"
            );


        if (!sessionToken) {

            return {
                statusCode: 401,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session required."
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

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Management session."
                })
            };
        }


        const session =
            sessions[0];


        if (session.revoked_at) {

            return {
                statusCode: 401,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "This Management session has been revoked."
                })
            };
        }


        if (
            new Date(session.expires_at).getTime()
            <= Date.now()
        ) {

            return {
                statusCode: 401,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Management session has expired."
                })
            };
        }


        /* =====================================
           GET FOUNDER ACCOUNT
        ===================================== */

        const founderResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?id=eq.${encodeURIComponent(session.management_account_id)}` +
                `&select=id,management_id,full_name,assigned_role,account_status`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!founderResponse.ok) {

            throw new Error(
                "Unable to retrieve Founder account."
            );
        }


        const founders =
            await founderResponse.json();


        if (!founders.length) {

            return {
                statusCode: 403,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Founder account not found."
                })
            };
        }


        const founder =
            founders[0];


        if (
            founder.assigned_role !== "Founder"
            ||
            founder.account_status !== "ACTIVE"
        ) {

            return {
                statusCode: 403,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Founder authorization required."
                })
            };
        }


        /* =====================================
           READ REQUEST
        ===================================== */

        let data;

        try {

            data =
                JSON.parse(
                    event.body || "{}"
                );

        } catch {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid request data."
                })
            };
        }


        const fullName =
            String(data.fullName || "").trim();

        const email =
            String(data.email || "").trim();

        const phone =
            String(data.phone || "").trim();

        const role =
            String(data.role || "").trim();

        const password =
            String(data.password || "").trim();


        if (
            !fullName ||
            !email ||
            !phone ||
            !role
        ) {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Full name, email, phone and role are required."
                })
            };
        }


        /* =====================================
           ROLE MAP
        ===================================== */

        const roleMap = {

            "Production Manager": {
                department:
                    "Production Management"
            },

            "Digital / Website Manager": {
                department:
                    "Digital / Website Management"
            },

            "Media Manager": {
                department:
                    "Media Management"
            },

            "Finance & Accounts Officer": {
                department:
                    "Finance & Accounts"
            },

            "Security Officer": {
                department:
                    "Security Management"
            },

            "Music / Artist Manager": {
                department:
                    "Music / Artist Management"
            },

            "Distribution Manager": {
                department:
                    "Distribution Management"
            },

            "Public Relations Officer": {
                department:
                    "Public Relations"
            },

            "Monitoring / Supervisor": {
                department:
                    "Monitoring & Supervision"
            },

            "Support Team": {
                department:
                    "Management Support"
            }

        };


        if (!roleMap[role]) {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Invalid Management role selected."
                })
            };
        }


        /* =====================================
           PREVENT DUPLICATE ROLE
        ===================================== */

        const roleResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?assigned_role=eq.${encodeURIComponent(role)}` +
                `&account_status=eq.ACTIVE` +
                `&select=id,management_id,full_name`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!roleResponse.ok) {

            throw new Error(
                "Unable to check Management role."
            );
        }


        const existingRole =
            await roleResponse.json();


        if (existingRole.length > 0) {

            return {
                statusCode: 409,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        `The ${role} position is already occupied. Please choose another role.`
                })
            };
        }


        /* =====================================
           CHECK EMAIL
        ===================================== */

        const emailResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?email=eq.${encodeURIComponent(email)}` +
                `&select=id,management_id`,
                {
                    method: "GET",

                    headers: {
                        apikey: supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!emailResponse.ok) {

            throw new Error(
                "Unable to check email."
            );
        }


        const existingEmail =
            await emailResponse.json();


        if (existingEmail.length > 0) {

            return {
                statusCode: 409,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "An account with this email already exists."
                })
            };
        }


        /* =====================================
           MANAGEMENT ID
        ===================================== */

        let managementId;

        let idExists = true;


        while (idExists) {

            managementId =
                generateManagementId();


            const idResponse =
                await fetch(
                    `${supabaseUrl}/rest/v1/management_accounts` +
                    `?management_id=eq.${encodeURIComponent(managementId)}` +
                    `&select=id`,
                    {
                        method: "GET",

                        headers: {
                            apikey: supabaseKey,

                            Authorization:
                                `Bearer ${supabaseKey}`
                        }
                    }
                );


            if (!idResponse.ok) {

                throw new Error(
                    "Unable to check Management ID."
                );
            }


            const existingId =
                await idResponse.json();


            idExists =
                existingId.length > 0;
        }


        /* =====================================
           PASSWORD
        ===================================== */

        let temporaryPassword =
            password;


        if (!temporaryPassword) {

            temporaryPassword =
                generatePassword(10);
        }


        if (temporaryPassword.length < 8) {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    message:
                        "Password must contain at least 8 characters."
                })
            };
        }


        const passwordHash =
            hashPassword(
                temporaryPassword
            );


        /* =====================================
           CREATE ACCOUNT
        ===================================== */

        const insertResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts`,
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

                        management_id:
                            managementId,

                        management_application_id:
                            null,

                        full_name:
                            fullName,

                        email:
                            email,

                        phone:
                            phone,

                        assigned_role:
                            role,

                        department:
                            roleMap[role].department,

                        password_hash:
                            passwordHash,

                        account_status:
                            "ACTIVE",

                        created_by:
                            founder.id

                    })
                }
            );


        if (!insertResponse.ok) {

            const errorText =
                await insertResponse.text();

            console.error(
                "Management account creation failed:",
                errorText
            );

            throw new Error(
                "Unable to create Management account."
            );
        }


        const createdAccount =
            await insertResponse.json();


        /* =====================================
           RESPONSE
        ===================================== */

        return {

            statusCode: 201,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                success: true,

                message:
                    "Management account created successfully.",

                management: {

                    managementId:
                        managementId,

                    fullName:
                        fullName,

                    email:
                        email,

                    phone:
                        phone,

                    role:
                        role,

                    department:
                        roleMap[role].department,

                    accountStatus:
                        "ACTIVE",

                    temporaryPassword:
                        temporaryPassword

                }

            })
        };


    } catch (error) {

        console.error(
            "Founder create Management error:",
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
                    "An internal server error occurred."
            })
        };
    }
};