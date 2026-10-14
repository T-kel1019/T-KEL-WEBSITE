const { randomUUID } = require("crypto");

exports.handler = async function (event) {
    const headers = {
        "Content-Type": "application/json"
    };

    function respond(statusCode, data) {
        return {
            statusCode,
            headers,
            body: JSON.stringify(data)
        };
    }

    if (event.httpMethod !== "POST") {
        return respond(405, {
            success: false,
            error: "Method not allowed."
        });
    }

    let createdUserId = null;
    let supabaseUrl = null;
    let supabaseKey = null;

    try {
        const {
            fullName,
            artistName,
            email,
            phone,
            country,
            password,
            reference
        } = JSON.parse(event.body || "{}");

        if (
            !fullName ||
            !artistName ||
            !email ||
            !phone ||
            !country ||
            !password ||
            !reference
        ) {
            return respond(400, {
                success: false,
                error: "All required fields must be provided."
            });
        }

        if (String(password).length < 8) {
            return respond(400, {
                success: false,
                error: "Password must be at least 8 characters long."
            });
        }

        const normalizedEmail =
            String(email).trim().toLowerCase();

        const normalizedReference =
            String(reference).trim().toUpperCase();

        const normalizedFullName =
            String(fullName).trim();

        const normalizedArtistName =
            String(artistName).trim();

        const normalizedPhone =
            String(phone).trim();

        const normalizedCountry =
            String(country).trim();

        supabaseUrl = process.env.SUPABASE_URL;
        supabaseKey = process.env.SUPABASE_SECRET_KEY;

        if (!supabaseUrl || !supabaseKey) {
            console.error(
                "Missing server-side Supabase configuration."
            );

            return respond(500, {
                success: false,
                error: "Server configuration error."
            });
        }

        const baseUrl = supabaseUrl.replace(/\/+$/, "");

        const adminHeaders = {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            "Content-Type": "application/json"
        };

        /*
         * 1. Verify the exact approved application.
         */

        const applicationUrl =
            `${baseUrl}/rest/v1/applications` +
            `?application_reference=eq.${encodeURIComponent(normalizedReference)}` +
            `&email=eq.${encodeURIComponent(normalizedEmail)}` +
            `&category=eq.Music%20Artist` +
            `&application_status=eq.approved` +
            `&select=id,full_name,email,application_reference` +
            `&limit=1`;

        const applicationResponse = await fetch(
            applicationUrl,
            {
                method: "GET",
                headers: adminHeaders
            }
        );

        if (!applicationResponse.ok) {
            console.error(
                "Application verification failed:",
                await applicationResponse.text()
            );

            return respond(500, {
                success: false,
                error: "Unable to verify your application."
            });
        }

        const applications =
            await applicationResponse.json();

        if (
            !Array.isArray(applications) ||
            applications.length !== 1
        ) {
            return respond(403, {
                success: false,
                error:
                    "The reference and email do not match an approved Music Artist application."
            });
        }

        const application = applications[0];

        /*
         * 2. Confirm the legal name matches the application.
         */

        if (
            String(application.full_name || "")
                .trim()
                .toLowerCase() !==
            normalizedFullName.toLowerCase()
        ) {
            return respond(403, {
                success: false,
                error:
                    "The legal name must match the approved application."
            });
        }

        /*
         * 3. Check whether the email already has an account.
         */

        let existingUser = null;
        let page = 1;
        const perPage = 1000;

        while (true) {
            const usersResponse = await fetch(
                `${baseUrl}/auth/v1/admin/users?page=${page}&per_page=${perPage}`,
                {
                    method: "GET",
                    headers: adminHeaders
                }
            );

            if (!usersResponse.ok) {
                console.error(
                    "Unable to check existing users:",
                    await usersResponse.text()
                );

                return respond(500, {
                    success: false,
                    error: "Unable to check your existing account."
                });
            }

            const usersData = await usersResponse.json();

            const users = Array.isArray(usersData.users)
                ? usersData.users
                : [];

            existingUser = users.find(
                user =>
                    String(user.email || "")
                        .trim()
                        .toLowerCase() === normalizedEmail
            );

            if (existingUser) {
                return respond(409, {
                    success: false,
                    error:
                        "An account already exists for this email. Please sign in or use Forgot password."
                });
            }

            if (users.length < perPage) {
                break;
            }

            page++;
        }

        /*
         * 4. Create the authentication account.
         */

        const createUserResponse = await fetch(
            `${baseUrl}/auth/v1/admin/users`,
            {
                method: "POST",
                headers: adminHeaders,
                body: JSON.stringify({
                    email: normalizedEmail,
                    password: String(password),
                    email_confirm: true,
                    user_metadata: {
                        full_name: normalizedFullName,
                        artist_name: normalizedArtistName,
                        phone: normalizedPhone,
                        country: normalizedCountry,
                        application_reference: normalizedReference
                    }
                })
            }
        );

        const userText = await createUserResponse.text();

        let user = {};

        try {
            user = userText ? JSON.parse(userText) : {};
        } catch {
            console.error(
                "Invalid authentication response."
            );

            return respond(500, {
                success: false,
                error: "Unable to read the account-creation response."
            });
        }

        if (!createUserResponse.ok || !user.id) {
            console.error(
                "Authentication account creation failed:",
                user
            );

            return respond(400, {
                success: false,
                error:
                    user.msg ||
                    user.message ||
                    user.error_description ||
                    user.error ||
                    "Unable to create your account."
            });
        }

        createdUserId = user.id;

        /*
         * 5. Create the Distribution artist profile.
         */

        const artistResponse = await fetch(
            `${baseUrl}/rest/v1/artists`,
            {
                method: "POST",
                headers: {
                    ...adminHeaders,
                    Prefer: "return=minimal"
                },
               body: JSON.stringify({
    id: randomUUID(),
    user_id: user.id,
    artist_name: normalizedArtistName,
    legal_name: normalizedFullName,
    email: normalizedEmail,
    phone: normalizedPhone,
    country: normalizedCountry,
    status: "active",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
})
            }
        );

        if (!artistResponse.ok) {
            throw new Error(
                "Could not create the Distribution artist profile: " +
                await artistResponse.text()
            );
        }

        /*
         * 6. Create the companion artist profile.
         */

        const profileResponse = await fetch(
            `${baseUrl}/rest/v1/artist_profiles`,
            {
                method: "POST",
                headers: {
                    ...adminHeaders,
                    Prefer: "return=minimal"
                },
              body: JSON.stringify({
    id: user.id,
    user_id: user.id,
    full_name: normalizedFullName,
    artist_name: normalizedArtistName,
    phone: normalizedPhone,
    country: normalizedCountry,
    created_at: new Date().toISOString()
})
            }
        );

        if (!profileResponse.ok) {
            throw new Error(
                "Could not create the companion artist profile: " +
                await profileResponse.text()
            );
        }

        /*
         * 7. Report success only after both profiles exist.
         */

        return respond(200, {
            success: true,
            message:
                "Your T-KEL Artist Account and profiles were created successfully.",
            user: {
                id: user.id,
                email: normalizedEmail,
                full_name: normalizedFullName,
                artist_name: normalizedArtistName,
                phone: normalizedPhone,
                country: normalizedCountry,
                application_reference: normalizedReference
            }
        });

    } catch (error) {
        console.error(
            "Artist account setup failed:",
            error.message
        );

        /*
         * Attempt to roll back the newly created authentication user.
         * Foreign-key cascades may remove related profiles as well.
         */

        if (createdUserId && supabaseUrl && supabaseKey) {
            try {
                const baseUrl = supabaseUrl.replace(/\/+$/, "");

                const cleanupResponse = await fetch(
                    `${baseUrl}/auth/v1/admin/users/${encodeURIComponent(createdUserId)}`,
                    {
                        method: "DELETE",
                        headers: {
                            apikey: supabaseKey,
                            Authorization: `Bearer ${supabaseKey}`
                        }
                    }
                );

                if (!cleanupResponse.ok) {
                    console.error(
                        "Automatic cleanup failed; administrator review is required."
                    );
                }
            } catch (cleanupError) {
                console.error(
                    "Automatic cleanup could not be completed."
                );
            }
        }

        return respond(500, {
            success: false,
            error:
                "Account setup did not finish. Please contact T-KEL support before retrying."
        });
    }
};