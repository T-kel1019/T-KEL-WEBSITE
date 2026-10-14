const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const MAX_PHOTO_SIZE = 5 * 1024 * 1024; // 5 MB

const ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/png",
    "image/webp"
];

exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Method not allowed"
            })
        };
    }

    try {

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseSecret =
            process.env.SUPABASE_SECRET_KEY;

        if (!supabaseUrl || !supabaseSecret) {
            console.error(
                "Supabase environment variables are missing."
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Application system is not configured."
                })
            };
        }

        // --------------------------------------------------
        // 1. Parse multipart form
        // --------------------------------------------------

        const contentType =
            event.headers?.["content-type"] ||
            event.headers?.["Content-Type"] ||
            "";

        if (
            !contentType.toLowerCase().includes(
                "multipart/form-data"
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
                        "Invalid form submission."
                })
            };
        }

        const boundaryMatch =
            contentType.match(
                /boundary=(?:"([^"]+)"|([^;]+))/i
            );

        if (!boundaryMatch) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Invalid form data."
                })
            };
        }

        const boundary =
            boundaryMatch[1] ||
            boundaryMatch[2];

        const rawBody =
            event.isBase64Encoded
                ? Buffer.from(
                    event.body || "",
                    "base64"
                )
                : Buffer.from(
                    event.body || "",
                    "utf8"
                );

        // --------------------------------------------------
        // 2. Parse multipart data
        // --------------------------------------------------

        const parts =
            rawBody.toString("binary")
                .split("--" + boundary);

        const fields = {};
        let photo = null;

        for (const part of parts) {

            if (
                !part ||
                part === "--\r\n" ||
                part === "--"
            ) {
                continue;
            }

            const headerEnd =
                part.indexOf("\r\n\r\n");

            if (headerEnd === -1) {
                continue;
            }

            const headerText =
                part.slice(0, headerEnd);

            let content =
                part.slice(headerEnd + 4);

            if (content.endsWith("\r\n")) {
                content =
                    content.slice(
                        0,
                        -2
                    );
            }

            const nameMatch =
                headerText.match(
                    /name="([^"]+)"/i
                );

            if (!nameMatch) {
                continue;
            }

            const fieldName =
                nameMatch[1];

            const fileNameMatch =
                headerText.match(
                    /filename="([^"]*)"/i
                );

            const typeMatch =
                headerText.match(
                    /Content-Type:\s*([^\r\n]+)/i
                );

            // ----------------------------------------------
            // File
            // ----------------------------------------------

            if (fileNameMatch) {

                const originalName =
                    fileNameMatch[1];

                const mimeType =
                    (
                        typeMatch
                            ? typeMatch[1]
                            : ""
                    )
                    .trim()
                    .toLowerCase();

                if (
                    !originalName ||
                    !content
                ) {
                    continue;
                }

                const fileBuffer =
                    Buffer.from(
                        content,
                        "binary"
                    );

                photo = {
                    originalName:
                        originalName,
                    mimeType:
                        mimeType,
                    buffer:
                        fileBuffer
                };

            } else {

                // ------------------------------------------
                // Normal field
                // ------------------------------------------

                fields[fieldName] =
                    Buffer.from(
                        content,
                        "binary"
                    ).toString("utf8");
            }
        }

        // --------------------------------------------------
        // 3. Read payment reference
        // --------------------------------------------------

        const paymentReference =
    String(
        fields.paymentReference || ""
    ).trim()
    .toUpperCase();
        if (!paymentReference) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Payment reference is required."
                })
            };
        }

        // --------------------------------------------------
        // 4. Create Supabase admin client
        // --------------------------------------------------

        const supabase =
            createClient(
                supabaseUrl,
                supabaseSecret
            );

        // --------------------------------------------------
        // 5. Find application using payment reference
        // --------------------------------------------------

        const {
            data: application,
            error:
                applicationError
        } = await supabase
            .from("applications")
            .select(`
                id,
                application_reference,
                full_name,
                email,
                phone,
                date_of_birth,
                gender,
                category,
                experience,
                application_status,
                payment_status,
                payment_reference
            `)
            .eq(
                "payment_reference",
                paymentReference
            )
            .maybeSingle();

        if (applicationError) {

            console.error(
                "Application lookup error:",
                applicationError
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to verify your payment."
                })
            };
        }

        if (!application) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Payment reference not found."
                })
            };
        }

        // --------------------------------------------------
        // 6. Confirm application approval
        // --------------------------------------------------

        if (
            String(
                application.application_status || ""
            ).toLowerCase() !== "approved"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This application has not been approved."
                })
            };
        }

        // --------------------------------------------------
        // 7. Confirm payment
        // --------------------------------------------------

        if (
            String(
                application.payment_status || ""
            ).toLowerCase() !== "paid"
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Your payment has not been verified."
                })
            };
        }

        // --------------------------------------------------
        // 8. Confirm stored payment reference
        // --------------------------------------------------

        if (
            application.payment_reference !==
            paymentReference
        ) {

            console.error(
                "Payment reference mismatch."
            );

            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This payment reference does not match your application."
                })
            };
        }

        // --------------------------------------------------
        // 9. Prevent duplicate form submission
        // --------------------------------------------------

        const {
            data: existingForm,
            error: existingFormError
        } = await supabase
            .from("application_forms")
            .select("id")
            .eq(
                "application_id",
                application.id
            )
            .maybeSingle();

        if (existingFormError) {

            console.error(
                "Existing form check error:",
                existingFormError
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to check application form status."
                })
            };
        }

        if (existingForm) {
            return {
                statusCode: 409,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    alreadySubmitted: true,
                    error:
                        "This T-KEL application form has already been submitted."
                })
            };
        }

        // --------------------------------------------------
        // 10. Read submitted fields
        // --------------------------------------------------

        const fullName =
            String(
                fields.fullName || ""
            ).trim();

        const professionalName =
            String(
                fields.professionalName || ""
            ).trim();

        const email =
            String(
                fields.email || ""
            )
            .trim()
            .toLowerCase();

        const phone =
            String(
                fields.phone || ""
            ).trim();

        const dateOfBirth =
            String(
                fields.dateOfBirth || ""
            ).trim();

        const gender =
            String(
                fields.gender || ""
            ).trim();

        const country =
            String(
                fields.country || ""
            ).trim();

        const state =
            String(
                fields.state || ""
            ).trim();

        const city =
            String(
                fields.city || ""
            ).trim();

        const category =
            String(
                fields.category || ""
            ).trim();

        const experience =
            String(
                fields.experience || ""
            ).trim();

        const skills =
            String(
                fields.skills || ""
            ).trim();

        const socialMedia =
            String(
                fields.socialMedia || ""
            ).trim();

        const reasonForJoining =
            String(
                fields.reasonForJoining || ""
            ).trim();
const additionalInformation =
    String(
        fields.additionalInformation || ""
    ).trim();
        const termsAccepted =
    String(
        fields.termsAccepted || ""
    ).trim().toLowerCase();

        // --------------------------------------------------
        // 11. Required fields
        // --------------------------------------------------

        if (
    !fullName ||
    !email ||
    !phone ||
    !dateOfBirth ||
    !gender ||
    !country ||
    !state ||
    !city ||
    !category ||
    termsAccepted !== "true"
) {            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
    "Please complete all required fields and accept the terms and policies."   })
            };
        }

        // --------------------------------------------------
        // 12. Make sure submitted name matches application
        // --------------------------------------------------

        if (
            fullName.toLowerCase() !==
            String(
                application.full_name || ""
            )
            .trim()
            .toLowerCase()
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "The name does not match the original application."
                })
            };
        }

        // --------------------------------------------------
        // 13. Make sure submitted email matches application
        // --------------------------------------------------

        if (
            email !==
            String(
                application.email || ""
            )
            .trim()
            .toLowerCase()
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "The email address does not match the original application."
                })
            };
        }

        // --------------------------------------------------
        // 14. Make sure category cannot be changed
        // --------------------------------------------------

        if (
            category.toLowerCase() !==
            String(
                application.category || ""
            )
            .trim()
            .toLowerCase()
        ) {
            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "The selected category does not match the original application."
                })
            };
        }

      // --------------------------------------------------
// 15. Make sure phone matches original application
// --------------------------------------------------

const submittedPhone =
    phone.replace(/[\s\-()]/g, "");

const originalPhone =
    String(
        application.phone || ""
    )
    .trim()
    .replace(/[\s\-()]/g, "");

if (
    submittedPhone !== originalPhone
) {
    return {
        statusCode: 403,
        headers: {
            "Content-Type":
                "application/json"
        },
        body: JSON.stringify({
            error:
                "The phone number does not match the original application."
        })
    };
}
      
        // --------------------------------------------------
        // 16. Validate profile photo
        // --------------------------------------------------

        if (photo) {

            if (
                !ALLOWED_IMAGE_TYPES.includes(
                    photo.mimeType
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
                            "Profile photo must be JPG, PNG, or WebP."
                    })
                };
            }

            if (
                photo.buffer.length >
                MAX_PHOTO_SIZE
            ) {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        error:
                            "Profile photo must be 5 MB or smaller."
                    })
                };
            }
        }

        // --------------------------------------------------
        // 17. Upload profile photo
        // --------------------------------------------------

        let profilePhotoUrl = null;

        if (photo) {

            const extensionMap = {
                "image/jpeg": "jpg",
                "image/png": "png",
                "image/webp": "webp"
            };

            const extension =
                extensionMap[
                    photo.mimeType
                ];

            const randomName =
                crypto
                    .randomBytes(16)
                    .toString("hex");

            const filePath =
                "application-forms/" +
                application.application_reference +
                "-" +
                randomName +
                "." +
                extension;

            const {
                error: uploadError
            } = await supabase.storage
                .from("applicant-photos")
                .upload(
                    filePath,
                    photo.buffer,
                    {
                        contentType:
                            photo.mimeType,
                        upsert: false
                    }
                );

            if (uploadError) {

                console.error(
                    "Profile photo upload error:",
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
                            "Unable to upload profile photo."
                    })
                };
            }

            const {
                data: publicUrlData
            } = supabase.storage
                .from("applicant-photos")
                .getPublicUrl(
                    filePath
                );

            profilePhotoUrl =
                publicUrlData?.publicUrl ||
                null;
        }

        // --------------------------------------------------
        // 18. Insert completed application form
        // --------------------------------------------------

        const {
            data: insertedForm,
            error: insertError
        } = await supabase
            .from("application_forms")
            .insert({
                application_id:
                    application.id,

                application_reference:
                    application.application_reference,

                full_name:
                    application.full_name,

                professional_name:
                    professionalName || null,

                email:
                    application.email,

                phone:
                    phone,

                date_of_birth:
                    dateOfBirth,

                gender:
                    gender,

                country:
                    country,

                state:
                    state,

                city:
                    city,

                category:
                    application.category,

                experience:
                    experience || null,

                skills:
                    skills || null,

                social_media:
                    socialMedia || null,

                reason_for_joining:
                    reasonForJoining || null,

                additional_information:
                    additionalInformation || null,

                profile_photo_url:
                    profilePhotoUrl
            })
            .select("id")
            .single();

        if (insertError) {

            console.error(
                "Application form insert error:",
                insertError
            );

            // Unique constraint means another request
            // may have submitted it first.
            if (
                insertError.code ===
                "23505"
            ) {
                return {
                    statusCode: 409,
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        success: false,
                        alreadySubmitted: true,
                        error:
                            "This T-KEL application form has already been submitted."
                    })
                };
            }

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to save your application form."
                })
            };
        }

        // --------------------------------------------------
        // 19. Success
        // --------------------------------------------------

        return {
            statusCode: 200,
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                success: true,
                formSubmitted: true,
                formId:
                    insertedForm?.id || null,
                applicationReference:
                    application.application_reference
            })
        };

    } catch (error) {

        console.error(
            "Application form submission error:",
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
                    "Something went wrong while submitting your application form."
            })
        };
    }
};