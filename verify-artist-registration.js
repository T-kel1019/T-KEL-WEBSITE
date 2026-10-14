exports.handler = async function (event) {
    const headers = {
        "Content-Type": "application/json"
    };

    function response(statusCode, data) {
        return {
            statusCode,
            headers,
            body: JSON.stringify(data)
        };
    }

    if (event.httpMethod !== "POST") {
        return response(405, {
            success: false,
            error: "Method not allowed."
        });
    }

    let createdUserId = null;

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
            return response(400, {
                success: false,
                error: "All required fields must be provided."
            });
        }

        if (String(password).length < 8) {
            return response(400, {
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

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;

        if (!supabaseUrl || !supabaseKey) {
            console.error(
                "Missing server-side Supabase configuration."
            );

            return response(500, {
                success: false,
                error: "Server configuration error."
            });
        }

        const baseUrl = supabaseUrl.replace(/\/+$/, "");

        const adminHeaders = {
            "apikey": supabaseKey,
            "Authorization": `Bearer ${supabaseKey}`,
            "Content-Type": "application/json"
        };

        /*
         * 1. Verify the exact approved Music Artist application.
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

            return response(500, {
                success: false,
                error: "Unable to verify your approved application."
            });
        }

        const applications =
            await applicationResponse.json();

        if (
            !Array.isArray(applications) ||
            applications.length !== 1
        ) {
            return response(403, {
                success: false,
                error:
                    "The reference number and email do not match an approved Music Artist application."
            });
        }

        /*
         * 2. Check whether the authentication account already exists.
         *
         * Existing users must recover or sign in to their accounts.
         * This function will not create a duplicate login.
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

                return response(500, {
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
                return response(409, {
                    success: false,
                    error:
                        "An account already exists for this email. Please use the login page and select Forgot password if necessary."
                });
            }

            if (users.length < perPage) {
                break;
            }

            page++;
        }

        /*
         * 3. Create the authentication user.
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

        const createUserText =
            await createUserResponse.text();

        let user = {};

        try {
            user = createUserText
                ? JSON.parse(createUserText)
                : {};
        } catch {
            console.error(
                "Invalid user-creation response:",
                createUserText
            );

            return response(500, {
                success: false,
                error: "Unable to read the account-creation response."
            });
        }

        if (!createUserResponse.ok || !user.id) {
            console.error(
                "Account creation failed:",
                user
            );

            return response(400, {
                success: false,
                error:
                    user.msg ||
                    user.message ||
                    user.error_description ||
                    user.error ||
                    "Unable to create your T-KEL account."
            });
        }

        createdUserId = user.id;

        /*
         * 4. Create the Distribution artist profile.
         */

        const artistProfileResponse = await fetch(
            `${baseUrl}/rest/v1/artists`,
            {
                method: "POST",
                headers: {
                    ...adminHeaders,
                    "Prefer": "return=representation"
                },
                body: JSON.stringify({
                    id: crypto.randomUUID(),
                    user_id: user.id,
                    artist_name: normalizedArtistName,
                    legal_name: normalizedFullName,
                    email: normalizedEmail,
                    phone: normalizedPhone,
                    country: normalizedCountry,
                    status: "active"
                })
            }
        );

        if (!artistProfileResponse.ok) {
            throw new Error(
                "The authentication account was created, but the Distribution artist profile could not be saved: " +
                await artistProfileResponse.text()
            );
        }

        /*
         * 5. Create the companion artist_profiles record.
         */

        const companionProfileResponse = await fetch(
            `${baseUrl}/rest/v1/artist_profiles`,
            {
                method: "POST",
                headers: {
                    ...adminHeaders,
                    "Prefer": "return=representation"
                },
                body: JSON.stringify({
                    id: user.id,
                    user_id: user.id,
                    full_name: normalizedFullName,
                    artist_name: normalizedArtistName,
                    phone: normalizedPhone,
                    country: normalizedCountry
                })
            }
        );

        if (!companionProfileResponse.ok) {
            throw new Error(
                "The Distribution profile was created, but the companion artist profile could not be saved: " +
                await companionProfileResponse.text()
            );
        }

        /*
         * 6. Report successful account creation.
         */

        return response(200, {
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
            "Create artist account error:",
            error.message
        );

        /*
         * Do not automatically delete an authentication user here.
         * A profile insertion might have partially succeeded, and
         * deleting the user could remove related records.
         */

        return response(500, {
            success: false,
            error:
                "Account setup did not finish successfully. Please contact T-KEL support before retrying."
        });
    }
};