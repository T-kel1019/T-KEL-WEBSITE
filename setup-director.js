const crypto = require("crypto");

function scryptAsync(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) {
                reject(err);
            } else {
                resolve(derivedKey);
            }
        });
    });
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

        const body = JSON.parse(event.body || "{}");

        const setupKey = body.setupKey;
        const password = body.password;

        if (!setupKey || !password) {
            return {
                statusCode: 400,
                body: JSON.stringify({
                    success: false,
                    message: "Setup key and password are required."
                })
            };
        }

        if (password.length < 10) {
            return {
                statusCode: 400,
                body: JSON.stringify({
                    success: false,
                    message: "Password must be at least 10 characters."
                })
            };
        }

        const expectedSetupKey =
            process.env.TKEL_DIRECTOR_SETUP_KEY;

        if (!expectedSetupKey) {
            throw new Error(
                "TKEL_DIRECTOR_SETUP_KEY is not configured."
            );
        }

        if (
            !crypto.timingSafeEqual(
                Buffer.from(setupKey),
                Buffer.from(expectedSetupKey)
            )
        ) {
            return {
                statusCode: 403,
                body: JSON.stringify({
                    success: false,
                    message: "Invalid setup key."
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

        const existingResponse = await fetch(
            `${supabaseUrl}/rest/v1/management_accounts?management_id=eq.TK8M4Q7X&select=id`,
            {
                method: "GET",
                headers: {
                    apikey: supabaseKey,
                    Authorization: `Bearer ${supabaseKey}`
                }
            }
        );

        if (!existingResponse.ok) {
            throw new Error(
                "Unable to check existing management account."
            );
        }

        const existingAccounts =
            await existingResponse.json();

        if (existingAccounts.length > 0) {
            return {
                statusCode: 409,
                body: JSON.stringify({
                    success: false,
                    message:
                        "Director account already exists."
                })
            };
        }

        const directorUserId =
            "88d4f9bc-321c-40d6-a4d0-9824c8b7e86b";

        const salt =
            crypto.randomBytes(16).toString("hex");

        const derivedKey =
            await scryptAsync(password, salt);

        const passwordHash =
            `scrypt:${salt}:${derivedKey.toString("hex")}`;

        const now =
            new Date().toISOString();

        const accountResponse = await fetch(
            `${supabaseUrl}/rest/v1/management_accounts`,
            {
                method: "POST",
                headers: {
                    apikey: supabaseKey,
                    Authorization: `Bearer ${supabaseKey}`,
                    "Content-Type": "application/json",
                    Prefer: "return=minimal"
                },
                body: JSON.stringify({
                    management_id: "TK8M4Q7X",
                    full_name: "T-KEL Management Director",
                    email: "terriken4@gmail.com",
                    assigned_role: "T-KEL Management Director",
                    department: "Executive Management",
                    password_hash: passwordHash,
                    account_status: "ACTIVE",
                    created_by: directorUserId,
                    created_at: now,
                    updated_at: now
                })
            }
        );

        if (!accountResponse.ok) {

            const errorText =
                await accountResponse.text();

            console.error(
                "Account creation error:",
                errorText
            );

            throw new Error(
                "Failed to create Director account."
            );
        }

        return {
            statusCode: 200,
            body: JSON.stringify({
                success: true,
                message:
                    "T-KEL Management Director account created successfully.",
                managementId: "TK8M4Q7X"
            })
        };

    } catch (error) {

        console.error(
            "Director setup error:",
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