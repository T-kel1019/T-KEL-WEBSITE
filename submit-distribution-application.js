const crypto = require("crypto");

exports.handler = async function (event) {

    /* =========================
       ALLOW POST ONLY
    ========================= */

    if (event.httpMethod !== "POST") {

        return {
            statusCode: 405,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                success: false,
                error:
                    "Method not allowed"
            })
        };
    }


    try {

        /* =========================
           READ REQUEST DATA
        ========================= */

        const {
            fullName,
            email,
            phone,
            location,
            experience,
            termsAccepted
        } =
            JSON.parse(
                event.body || "{}"
            );


        /* =========================
           VALIDATE REQUIRED FIELDS
        ========================= */

        if (
            !fullName ||
            !email ||
            !phone ||
            !location ||
            !experience ||
            termsAccepted !== true
        ) {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    error:
                        "Please complete all required fields and accept the terms and privacy policy."
                })
            };
        }


        /* =========================
           NORMALIZE DATA
        ========================= */

        const normalizedFullName =
            String(fullName)
                .trim();

        const normalizedEmail =
            String(email)
                .trim()
                .toLowerCase();

        const normalizedPhone =
            String(phone)
                .trim();

        const normalizedLocation =
            String(location)
                .trim();

        const normalizedExperience =
            String(experience)
                .trim();


        /* =========================
           VALIDATE EMAIL
        ========================= */

        const emailPattern =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


        if (
            !emailPattern.test(
                normalizedEmail
            )
        ) {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    error:
                        "Please enter a valid email address."
                })
            };
        }


        /* =========================
           SUPABASE CONFIGURATION
        ========================= */

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;

        const brevoApiKey =
            process.env.BREVO_API_KEY;


        if (
            !supabaseUrl ||
            !supabaseKey
        ) {

            console.error(
                "Missing SUPABASE_URL or SUPABASE_SECRET_KEY."
            );

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    error:
                        "Server configuration error."
                })
            };
        }


        /* =========================
           CREATE SERVER-SIDE
           APPLICATION REFERENCE
        ========================= */

        const randomPart =
            crypto
                .randomBytes(6)
                .toString("hex")
                .toUpperCase();

        const applicationReference =
            "TKEL-DIST-" +
            randomPart;


        /* =========================
           SAVE APPLICATION
        ========================= */

        const applicationResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/applications`,
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${supabaseKey}`,

                        "apikey":
                            supabaseKey,

                        "Content-Type":
                            "application/json",

                        "Prefer":
                            "return=representation"
                    },

                    body: JSON.stringify({

                        full_name:
                            normalizedFullName,

                        email:
                            normalizedEmail,

                        phone:
                            normalizedPhone,

                        location:
                            normalizedLocation,

                        category:
                            "Music Artist",

                        experience:
                            normalizedExperience,

                        application_status:
                            "pending",

                        application_reference:
                            applicationReference

                    })
                }
            );


        /* =========================
           CHECK DATABASE RESPONSE
        ========================= */

        if (
            !applicationResponse.ok
        ) {

            const databaseError =
                await applicationResponse.text();

            console.error(
                "Distribution application database error:",
                databaseError
            );

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    error:
                        "Your distribution application could not be saved."
                })
            };
        }


        const applicationData =
            await applicationResponse.json();


        if (
            !applicationData ||
            !applicationData.length
        ) {

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    success: false,
                    error:
                        "Your application was saved, but the application record could not be confirmed."
                })
            };
        }


        /* =========================
           SEND CONFIRMATION EMAIL
        ========================= */

        if (!brevoApiKey) {

            console.error(
                "BREVO_API_KEY is missing."
            );

            /*
             * The application has already
             * been saved successfully.
             * Do not tell the applicant
             * that the application failed.
             */
        } else {

            try {

                const brevoResponse =
                    await fetch(
                        "https://api.brevo.com/v3/smtp/email",
                        {
                            method: "POST",

                            headers: {
                                "accept":
                                    "application/json",

                                "api-key":
                                    brevoApiKey,

                                "content-type":
                                    "application/json"
                            },

                            body: JSON.stringify({

                                sender: {
                                    name:
                                        "T-KEL",

                                    email:
                                        "no-reply@t-kel.com"
                                },

                                to: [
                                    {
                                        email:
                                            normalizedEmail,

                                        name:
                                            normalizedFullName
                                    }
                                ],

                                subject:
                                    "T-KEL Distribution Application Received",

                                htmlContent: `

                                    <div
                                        style="
                                            font-family:Arial,sans-serif;
                                            line-height:1.6;
                                            max-width:600px;
                                            margin:auto;
                                            color:#222;
                                        "
                                    >

                                        <img
                                            src="https://t-kel.com/T-KEL%20logo.png"
                                            alt="T-KEL Logo"
                                            width="180"
                                            style="
                                                display:block;
                                                width:180px;
                                                max-width:100%;
                                                height:auto;
                                                margin:0 auto 20px;
                                            "
                                        >

                                        <h2
                                            style="
                                                color:#0066ff;
                                            "
                                        >
                                            Application Received
                                        </h2>

                                        <p>
                                            Hello ${normalizedFullName},
                                        </p>

                                        <p>
                                            Thank you for submitting your
                                            application to
                                            <strong>
                                                T-KEL Distribution
                                            </strong>.
                                        </p>

                                        <p>
                                            Your application has been
                                            successfully received and is now
                                            awaiting review by T-KEL Management.
                                        </p>

                                        <p>
                                            Please note that your application
                                            reference and further instructions
                                            will be sent to you by email after
                                            your application has been reviewed.
                                        </p>

                                        <p>
                                            Please do not submit another
                                            application while your current
                                            application is under review.
                                        </p>

                                        <p>
                                            <strong>
                                                Stay Real, Stay kelz.
                                            </strong>
                                        </p>

                                        <p>
                                            — T-KEL Management<br>
                                            Terriken Entertainment Limited
                                        </p>

                                    </div>

                                `
                            })
                        }
                    );


                const brevoText =
                    await brevoResponse.text();


                if (
                    !brevoResponse.ok
                ) {

                    console.error(
                        "Distribution confirmation email failed:",
                        {
                            status:
                                brevoResponse.status,

                            response:
                                brevoText
                        }
                    );

                } else {

                    console.log(
                        "Distribution confirmation email sent successfully."
                    );

                }

            } catch (emailError) {

                /*
                 * Do not fail the application
                 * because the email failed.
                 */

                console.error(
                    "Distribution email error:",
                    emailError
                );

            }
        }


        /* =========================
           SUCCESS
           DO NOT RETURN REFERENCE
        ========================= */

        return {
            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                success: true,

                message:
                    "Distribution application submitted successfully."

            })
        };


    } catch (error) {

        console.error(
            "Distribution application error:",
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
                error:
                    "Something went wrong while submitting your distribution application."
            })
        };
    }
};