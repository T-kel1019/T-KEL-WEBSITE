exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            body: JSON.stringify({
                error: "Method not allowed"
            })
        };
    }

    try {

        const { email } = JSON.parse(event.body || "{}");

        if (!email) {
            return {
                statusCode: 400,
                body: JSON.stringify({
                    error: "Email is required."
                })
            };
        }

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const serviceRoleKey =
            process.env.SUPABASE_SERVICE_ROLE_KEY;

        if (!supabaseUrl || !serviceRoleKey) {
            console.error(
                "Missing Supabase server environment variables."
            );

            return {
                statusCode: 500,
                body: JSON.stringify({
                    error:
                        "Server configuration error."
                })
            };
        }

        const query =
    `${supabaseUrl}/rest/v1/applications` +
    `?email=eq.${encodeURIComponent(email)}` +
    `&category=eq.Music%20Artist` +
    `&select=application_status,created_at` +
    `&order=created_at.desc` +
    `&limit=1`;
        const response = await fetch(query, {
            method: "GET",
            headers: {
                "apikey": serviceRoleKey,
                "Authorization":
                    `Bearer ${serviceRoleKey}`
            }
        });

        if (!response.ok) {

            const errorText =
                await response.text();

            console.error(
                "Supabase approval check error:",
                errorText
            );

            return {
                statusCode: 500,
                body: JSON.stringify({
                    error:
                        "Unable to check application status."
                })
            };
        }

        const applications =
            await response.json();

        if (!applications.length) {

            return {
                statusCode: 200,
                body: JSON.stringify({
                    found: false,
                    approved: false
                })
            };
        }

        const status =
            applications[0].application_status;

        return {
            statusCode: 200,
            body: JSON.stringify({
                found: true,
                approved:
                    status === "Approved"
            })
        };

    } catch (error) {

        console.error(
            "Distribution approval error:",
            error
        );

        return {
            statusCode: 500,
            body: JSON.stringify({
                error:
                    "Something went wrong while checking approval."
            })
        };
    }
};