const crypto = require("crypto");

exports.handler = async function (event) {

    /* =========================
       ALLOW POST ONLY
    ========================= */

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                success: false,
                error: "Method not allowed"
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
            dateOfBirth,
            gender,
            requestedRole,
            experience,
            photoBase64,
            photoType,
            termsAccepted
        } = JSON.parse(event.body || "{}");


        /* =========================
           VALIDATE REQUIRED FIELDS
        ========================= */

        if (
            !fullName ||
            !email ||
            !phone ||
            !location ||
            !requestedRole ||
            !experience ||
            termsAccepted !== true
        ) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    error:
                        "Please complete all required fields and accept the management rules and policies."
                })
            };
        }


        /* =========================
           NORMALIZE DATA
        ========================= */

        const normalizedFullName =
            String(fullName).trim();

        const normalizedEmail =
            String(email)
                .trim()
                .toLowerCase();

        const normalizedPhone =
            String(phone).trim();

        const normalizedLocation =
            String(location).trim();

        const normalizedRole =
            String(requestedRole).trim();

        const normalizedExperience =
            String(experience).trim();


        /* =========================
           VALIDATE EMAIL
        ========================= */

        const emailPattern =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailPattern.test(normalizedEmail)) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
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


        if (!supabaseUrl || !supabaseKey) {

            console.error(
                "Missing SUPABASE_URL or SUPABASE_SECRET_KEY."
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    error:
                        "Server configuration error."
                })
            };
        }


        /* =========================
           GENERATE MANAGEMENT
           APPLICATION REFERENCE
           
           EXAMPLE:
           TKEL-MA-7F4K92X8
        ========================= */

        const randomPart =
            crypto
                .randomBytes(5)
                .toString("hex")
                .toUpperCase();

        const managementApplicationReference =
            "TKEL-MA-" + randomPart;


        /* =========================
           PHOTO PROCESSING
        ========================= */

        let photoPath = null;

        if (photoBase64) {

            let extension;

            if (photoType === "image/png") {
                extension = "png";

            } else if (
                photoType === "image/jpeg" ||
                photoType === "image/jpg"
            ) {
                extension = "jpg";

            } else if (
                photoType === "image/webp"
            ) {
                extension = "webp";

            } else {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        success: false,
                        error:
                            "Please upload a JPG, PNG, or WebP image."
                    })
                };
            }


            const cleanedBase64 =
                String(photoBase64)
                    .replace(
                        /^data:image\/[a-zA-Z0-9.+-]+;base64,/,
                        ""
                    )
                    .trim();


            if (!cleanedBase64) {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        success: false,
                        error:
                            "Invalid applicant photo."
                    })
                };
            }


            const photoBuffer =
                Buffer.from(
                    cleanedBase64,
                    "base64"
                );


            const maxPhotoSize =
                5 * 1024 * 1024;


            if (
                photoBuffer.length >
                maxPhotoSize
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
                            "Applicant photo must not exceed 5 MB."
                    })
                };
            }


            const randomFileId =
                crypto
                    .randomBytes(16)
                    .toString("hex")
                    .toUpperCase();


            photoPath =
                `management-applications/${randomFileId}.${extension}`;


            const uploadResponse =
                await fetch(
                    `${supabaseUrl}/storage/v1/object/management-applicant-photos/${photoPath}`,
                    {
                        method: "POST",

                        headers: {
                            "Authorization":
                                `Bearer ${supabaseKey}`,

                            "apikey":
                                supabaseKey,

                            "Content-Type":
                                photoType,

                            "x-upsert":
                                "false"
                        },

                        body: photoBuffer
                    }
                );


            if (!uploadResponse.ok) {

                const uploadError =
                    await uploadResponse.text();

                console.error(
                    "Management applicant photo upload error:",
                    uploadError
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
                            "Unable to upload applicant photo."
                    })
                };
            }
        }


        /* =========================
           SAVE MANAGEMENT APPLICATION
        ========================= */

        const applicationResponse =
            await fetch(
                `${supabaseUrl}/rest/v1/management_applications`,
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

                        management_application_reference:
                            managementApplicationReference,

                        full_name:
                            normalizedFullName,

                        email:
                            normalizedEmail,

                        phone:
                            normalizedPhone,

                        location:
                            normalizedLocation,

                        date_of_birth:
                            dateOfBirth || null,

                        gender:
                            gender
                                ? String(gender).trim()
                                : null,

                        requested_role:
                            normalizedRole,

                        experience:
                            normalizedExperience,

                        photo_url:
                            photoPath,

                        application_status:
                            "pending"
                    })
                }
            );


        /* =========================
           CHECK DATABASE RESPONSE
        ========================= */

        if (!applicationResponse.ok) {

            const databaseError =
                await applicationResponse.text();

            console.error(
                "Management application database error:",
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
                        "Your management application could not be saved."
                })
            };
        }


        const applicationData =
            await applicationResponse.json();

        const application =
            Array.isArray(applicationData)
                ? applicationData[0]
                : applicationData;


        if (!application) {
            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    error:
                        "Application was saved, but the record could not be confirmed."
                })
            };
        }


        /* =========================
           SEND RECEIVED EMAIL
           
           IMPORTANT:
           The reference is NOT
           returned to the browser.
           
           It is kept for management
           processing.
        ========================= */

        if (brevoApiKey) {

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
                                    "T-KEL Management Application Received",

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
                                            Management Application Received
                                        </h2>

                                        <p>
                                            Hello ${normalizedFullName},
                                        </p>

                                        <p>
                                            Thank you for applying to join
                                            <strong>
                                                T-KEL Management
                                            </strong>.
                                        </p>

                                        <p>
                                            Your management application has
                                            been successfully received and is
                                            now awaiting review by authorized
                                            T-KEL Management.
                                        </p>

                                        <p>
                                            Your application will be reviewed
                                            before any management position is
                                            assigned.
                                        </p>

                                        <p>
                                            If your application is approved,
                                            T-KEL Management will contact you
                                            with the next instructions.
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


                const emailResponseText =
                    await brevoResponse.text();

                if (!brevoResponse.ok) {

                    console.error(
                        "Management confirmation email failed:",
                        {
                            status:
                                brevoResponse.status,

                            response:
                                emailResponseText
                        }
                    );

                } else {

                    console.log(
                        "Management confirmation email sent successfully."
                    );
                }

            } catch (emailError) {

                console.error(
                    "Management confirmation email error:",
                    emailError
                );
            }
        }


        /* =========================
           SUCCESS
           
           DO NOT RETURN THE
           MANAGEMENT APPLICATION
           REFERENCE.
           
           DO NOT RETURN A
           MANAGEMENT ID.
        ========================= */

        return {
            statusCode: 200,
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                status: "pending",
                message:
                    "Your T-KEL Management application has been submitted successfully. T-KEL Management will review your application and contact you by email."
            })
        };


    } catch (error) {

        console.error(
            "Management application error:",
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
                    "Something went wrong while submitting your management application."
            })
        };
    }
};