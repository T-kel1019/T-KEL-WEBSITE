const crypto = require("crypto");

function generateManagementId() {
    const characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let randomPart = "";

    for (let i = 0; i < 9; i++) {
        randomPart += characters[
            crypto.randomInt(0, characters.length)
        ];
    }

    /*
     * Example:
     * TKEL-91XJT75FM
     *
     * The final character is always M.
     */
    return "TKEL-" + randomPart.slice(0, 8) + "M";
}


function hashPassword(password) {
    return new Promise((resolve, reject) => {

        const salt =
            crypto.randomBytes(16).toString("hex");

        crypto.scrypt(
            password,
            salt,
            64,
            (error, derivedKey) => {

                if (error) {
                    reject(error);
                    return;
                }

                resolve(
                    `scrypt:${salt}:${derivedKey.toString("hex")}`
                );
            }
        );
    });
}


exports.handler = async (event) => {

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

        const {
            applicationId,
            verified,
            assignedRole,
            department,
            password
        } = JSON.parse(event.body || "{}");


        /*
         * ------------------------------------------------
         * REQUIRED INPUTS
         * ------------------------------------------------
         */

        if (!applicationId) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Application ID is required."
                })
            };
        }


        /*
         * PHYSICAL VERIFICATION MUST BE CONFIRMED
         * BY THE DIRECTOR.
         */

        if (verified !== true) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Physical verification must be completed before registration."
                })
            };
        }


        if (!assignedRole) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Assigned management role is required."
                })
            };
        }


        if (
            !password ||
            password.length < 8 ||
            password.length > 200
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management password must contain between 8 and 200 characters."
                })
            };
        }


        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;


        if (!supabaseUrl || !supabaseKey) {
            throw new Error(
                "Supabase environment variables are missing."
            );
        }


        /*
         * ------------------------------------------------
         * VERIFY DIRECTOR SESSION
         * ------------------------------------------------
         */

        const authHeader =
            event.headers.authorization ||
            event.headers.Authorization;


        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management Director authentication required."
                })
            };
        }


        const accessToken =
            authHeader
                .replace("Bearer ", "")
                .trim();


        const userResponse =
            await fetch(
                `${supabaseUrl}/auth/v1/user`,
                {
                    method: "GET",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
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
                        "Invalid or expired Director session."
                })
            };
        }


        const directorUser =
            await userResponse.json();


        if (!directorUser.id) {
            return {
                statusCode: 401,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director identity could not be verified."
                })
            };
        }


        /*
         * ------------------------------------------------
         * VERIFY ACTIVE MANAGEMENT DIRECTOR
         * ------------------------------------------------
         */

        const directorResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(directorUser.id)}&select=user_id,full_name,active`,
                {
                    method: "GET",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!directorResponse.ok) {
            throw new Error(
                "Unable to verify Director authorization."
            );
        }


        const directors =
            await directorResponse.json();


        if (
            !directors.length ||
            directors[0].active !== true
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "You are not authorized as an active T-KEL Management Director."
                })
            };
        }


        /*
         * ------------------------------------------------
         * GET THE APPLICATION
         * ------------------------------------------------
         */

        const applicationResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_applications?id=eq.${encodeURIComponent(applicationId)}&select=*`,
                {
                    method: "GET",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!applicationResponse.ok) {
            throw new Error(
                "Unable to retrieve the application."
            );
        }


        const applications =
            await applicationResponse.json();


        if (!applications.length) {
            return {
                statusCode: 404,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Management application not found."
                })
            };
        }


        const application =
            applications[0];


        /*
         * ONLY APPROVED APPLICATIONS CAN BECOME
         * MANAGEMENT ACCOUNTS.
         */

        if (
            application.application_status !==
            "approved"
        ) {
            return {
                statusCode: 409,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "Only an approved Management application can be registered."
                })
            };
        }


        /*
         * ------------------------------------------------
         * CHECK WHETHER THIS APPLICATION ALREADY
         * HAS A MANAGEMENT ACCOUNT
         * ------------------------------------------------
         */

        const existingResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts?management_application_id=eq.${encodeURIComponent(applicationId)}&select=id,management_id,account_status`,
                {
                    method: "GET",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!existingResponse.ok) {
            throw new Error(
                "Unable to check existing Management account."
            );
        }


        const existingAccounts =
            await existingResponse.json();


        if (existingAccounts.length) {
            return {
                statusCode: 409,
                headers: {
                    "Cache-Control": "no-store"
                },
                body: JSON.stringify({
                    success: false,
                    message:
                        "This application already has a Management account.",
                    managementId:
                        existingAccounts[0].management_id
                })
            };
        }


        /*
         * ------------------------------------------------
         * CHECK WHETHER THE SELECTED ROLE IS ALREADY
         * OCCUPIED BY AN ACTIVE MEMBER
         * ------------------------------------------------
         *
         * IMPORTANT:
         *
         * Only ACTIVE members occupy a role.
         *
         * REMOVED members do NOT block replacement.
         *
         * This preserves permanent role continuity.
         * ------------------------------------------------
         */

        const normalizedRole =
            String(assignedRole)
                .trim();

        const roleResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts` +
                `?assigned_role=ilike.${encodeURIComponent(normalizedRole)}` +
                `&account_status=eq.ACTIVE` +
                `&select=id,management_id,full_name,assigned_role`,
                {
                    method: "GET",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`
                    }
                }
            );


        if (!roleResponse.ok) {
            throw new Error(
                "Unable to check Management role availability."
            );
        }


        const activeRoleMembers =
            await roleResponse.json();


        if (activeRoleMembers.length) {

            const occupiedMember =
                activeRoleMembers[0];

            return {
                statusCode: 409,

                headers: {
                    "Cache-Control":
                        "no-store"
                },

                body: JSON.stringify({

                    success: false,

                    message:
                        `The ${normalizedRole} role is currently occupied by an active Management member.`,

                    assignedRole:
                        normalizedRole,

                    currentMember: {
                        managementId:
                            occupiedMember.management_id,

                        fullName:
                            occupiedMember.full_name,

                        assignedRole:
                            occupiedMember.assigned_role
                    }
                })
            };
        }


        /*
         * ------------------------------------------------
         * HASH THE PASSWORD
         * ------------------------------------------------
         */

        const passwordHash =
            await hashPassword(password);


        /*
         * ------------------------------------------------
         * GENERATE UNIQUE MANAGEMENT ID
         * ------------------------------------------------
         */

        let managementId = null;


        for (
            let attempt = 0;
            attempt < 5;
            attempt++
        ) {

            const candidate =
                generateManagementId();


            const collisionResponse =
                await fetch(
                    `${supabaseUrl}/rest/v1/management_accounts?management_id=eq.${encodeURIComponent(candidate)}&select=id`,
                    {
                        method: "GET",

                        headers: {
                            apikey:
                                supabaseKey,

                            Authorization:
                                `Bearer ${supabaseKey}`
                        }
                    }
                );


            if (!collisionResponse.ok) {
                throw new Error(
                    "Unable to check Management ID."
                );
            }


            const collisions =
                await collisionResponse.json();


            if (collisions.length === 0) {
                managementId =
                    candidate;
                break;
            }
        }


        if (!managementId) {
            throw new Error(
                "Unable to generate a unique Management ID."
            );
        }


        /*
         * ------------------------------------------------
         * CREATE MANAGEMENT ACCOUNT
         * ------------------------------------------------
         */

        const accountResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_accounts`,
                {
                    method: "POST",

                    headers: {
                        apikey:
                            supabaseKey,

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
                            application.id,

                        full_name:
                            application.full_name,

                        email:
                            application.email,

                        phone:
                            application.phone,

                        assigned_role:
                            normalizedRole,

                        department:
                            department || null,

                        password_hash:
                            passwordHash,

                        account_status:
                            "ACTIVE",

                        created_by:
                            directorUser.id
                    })
                }
            );


        if (!accountResponse.ok) {

            const errorText =
                await accountResponse.text();

            console.error(
                "Management account creation error:",
                errorText
            );

            throw new Error(
                "Failed to create Management account."
            );
        }


        const createdAccounts =
            await accountResponse.json();


        if (!createdAccounts.length) {
            throw new Error(
                "Management account was not returned."
            );
        }


        const createdAccount =
            createdAccounts[0];


        /*
         * ------------------------------------------------
         * AUDIT LOG
         * ------------------------------------------------
         */

        const auditResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_audit_logs`,
                {
                    method: "POST",

                    headers: {
                        apikey:
                            supabaseKey,

                        Authorization:
                            `Bearer ${supabaseKey}`,

                        "Content-Type":
                            "application/json",

                        Prefer:
                            "return=minimal"
                    },

                    body: JSON.stringify({

                        actor_user_id:
                            directorUser.id,

                        actor_role:
                            "Management Director",

                        action:
                            "CREATE_MANAGEMENT_ACCOUNT",

                        target_type:
                            "management_account",

                        target_id:
                            createdAccount.id,

                        description:
                            `Created Management account ${managementId} for ${application.full_name}.`
                    })
                }
            );


        if (!auditResponse.ok) {
            console.error(
                "Management audit log error:",
                await auditResponse.text()
            );
        }


        /*
         * ------------------------------------------------
         * SUCCESS
         * ------------------------------------------------
         */

        return {
            statusCode: 201,

            headers: {
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store"
            },

            body: JSON.stringify({

                success: true,

                message:
                    "Management account created successfully.",

                managementId:
                    managementId,

                fullName:
                    application.full_name,

                email:
                    application.email,

                assignedRole:
                    normalizedRole,

                department:
                    department || null,

                accountStatus:
                    "ACTIVE"
            })
        };


    } catch (error) {

        console.error(
            "Management registration error:",
            error
        );


        return {
            statusCode: 500,

            headers: {
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store"
            },

            body: JSON.stringify({
                success: false,

                message:
                    "An internal server error occurred."
            })
        };
    }
};