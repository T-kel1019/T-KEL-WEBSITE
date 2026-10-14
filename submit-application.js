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
            dateOfBirth,
            gender,
            category,
            experience,
            photoBase64,
            photoType,
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
            !dateOfBirth ||
            !gender ||
            !category ||
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
                    error:
                        "Please complete all required fields and accept the terms and policies."
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
                    error:
                        "Supabase configuration is missing."
                })
            };
        }


        /* =========================
           NORMALIZE EMAIL
        ========================= */

        const normalizedEmail =
            String(email)
                .trim()
                .toLowerCase();


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
                    error:
                        "Please enter a valid email address."
                })
            };
        }


        /* =========================
           VALIDATE PHOTO TYPE
        ========================= */

        let extension;


        if (
            photoType ===
            "image/png"
        ) {

            extension =
                "png";

        } else if (
            photoType ===
                "image/jpeg" ||
            photoType ===
                "image/jpg"
        ) {

            extension =
                "jpg";

        } else if (
            photoType ===
            "image/webp"
        ) {

            extension =
                "webp";

        } else {

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    error:
                        "Please upload a JPG, PNG, or WebP image."
                })
            };
        }


        /* =========================
           CLEAN PHOTO DATA
        ========================= */

        const cleanedBase64 =
            String(
                photoBase64 || ""
            )
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
                    error:
                        "Invalid applicant photo."
                })
            };
        }


        /* =========================
           CONVERT PHOTO
        ========================= */

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
                    error:
                        "Applicant photo must not exceed 5 MB."
                })
            };
        }


        /* =========================
           CREATE PHOTO FILE ID
        ========================= */

        const randomFileId =
            crypto
                .randomBytes(16)
                .toString("hex")
                .toUpperCase();


        const photoPath =
            `applications/${randomFileId}.${extension}`;


        /* =========================
           UPLOAD PHOTO
        ========================= */

        const uploadResponse =
            await fetch(
                `${supabaseUrl}/storage/v1/object/applicant-photos/${photoPath}`,
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

                    body:
                        photoBuffer
                }
            );


        if (
            !uploadResponse.ok
        ) {

            const uploadError =
                await uploadResponse.text();

            console.error(
                "Photo upload error:",
                uploadError
            );

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    error:
                        "Unable to upload applicant photo."
                })
            };
        }


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
                            String(
                                fullName
                            ).trim(),

                        email:
                            normalizedEmail,

                        phone:
                            String(
                                phone
                            ).trim(),

                        location:
                            String(
                                location
                            ).trim(),

                        date_of_birth:
                            dateOfBirth,

                        gender:
                            String(
                                gender
                            ).trim(),

                        experience:
                            String(
                                experience
                            ).trim(),

                        category:
                            String(
                                category
                            ).trim(),

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

        if (
            !applicationResponse.ok
        ) {

            const databaseError =
                await applicationResponse.text();

            console.error(
                "Database error:",
                databaseError
            );

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    error:
                        "Application could not be saved."
                })
            };
        }


        const applicationData =
            await applicationResponse.json();


        const application =
            Array.isArray(
                applicationData
            )
                ? applicationData[0]
                : applicationData;


        if (
            !application
        ) {

            return {
                statusCode: 500,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    error:
                        "Application was saved, but the application record could not be confirmed."
                })
            };
        }


        /* =========================
           SUCCESS
           
           IMPORTANT:
           DO NOT RETURN THE
           APPLICATION REFERENCE
           TO THE APPLICANT.
           
           DO NOT SEND AN EMAIL
           FROM THIS FUNCTION.
           
           THE MANAGEMENT APPROVAL
           PROCESS WILL SEND THE
           REFERENCE AFTER APPROVAL.
        ========================= */

        return {
            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                success:
                    true,

                status:
                    application.application_status ||
                    "pending",

                message:
                    "Application submitted successfully. T-KEL Management will review your application and send further instructions by email."

            })
        };


    } catch (error) {

        console.error(
            "Application error:",
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
                    "Something went wrong while submitting the application."
            })
        };
    }
};