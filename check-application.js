const { createClient } = require("@supabase/supabase-js");

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

        const body =
            JSON.parse(event.body || "{}");


        const reference =
            String(
                body.reference || ""
            )
            .trim()
            .toUpperCase();


        if (!reference) {

            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Please enter your application reference."
                })
            };

        }


        const supabaseUrl =
            process.env.SUPABASE_URL;


        const supabaseKey =
            process.env.SUPABASE_SECRET_KEY;


        if (
            !supabaseUrl ||
            !supabaseKey
        ) {

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
                        "Server configuration error."
                })
            };

        }


        const supabase =
            createClient(
                supabaseUrl,
                supabaseKey
            );


        /*
        ==================================================
        FIRST: CHECK NORMAL T-KEL APPLICATIONS
        ==================================================
        */

        const {
            data: generalApplication,
            error: generalError
        } = await supabase

            .from("applications")

            .select(`
                id,
                application_reference,
                full_name,
                email,
                category,
                application_status,
                management_note,
                payment_status,
                payment_reference,
                payment_paid_at
            `)

            .eq(
                "application_reference",
                reference
            )

            .maybeSingle();


        if (generalError) {

            console.error(
                "General application lookup error:",
                generalError
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to check application status."
                })
            };

        }


        /*
        ==================================================
        NORMAL APPLICATION FOUND
        ==================================================
        */

        if (generalApplication) {

            return {
                statusCode: 200,

                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },

                body: JSON.stringify({

                    success: true,

                    applicationType:
                        "general",

                    application: {

                        type:
                            "general",

                        reference:
                            generalApplication.application_reference,

                        fullName:
                            generalApplication.full_name,

                        email:
                            generalApplication.email,

                        category:
                            generalApplication.category,

                        status:
                            generalApplication.application_status,

                        managementNote:
                            generalApplication.management_note || "",

                        paymentStatus:
                            generalApplication.payment_status ||
                            "unpaid",

                        paymentReference:
                            generalApplication.payment_reference ||
                            null,

                        paymentPaidAt:
                            generalApplication.payment_paid_at ||
                            null

                    }

                })

            };

        }


        /*
        ==================================================
        SECOND: CHECK MANAGEMENT APPLICATIONS
        ==================================================
        */

        const {
            data: managementApplication,
            error: managementError
        } = await supabase

            .from("management_applications")

            .select(`
                id,
                management_application_reference,
                full_name,
                email,
                requested_role,
                application_status,
                management_note
            `)

            .eq(
                "management_application_reference",
                reference
            )

            .maybeSingle();


        if (managementError) {

            console.error(
                "Management application lookup error:",
                managementError
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to check application status."
                })
            };

        }


        /*
        ==================================================
        MANAGEMENT APPLICATION FOUND
        ==================================================
        */

        if (managementApplication) {

            return {
                statusCode: 200,

                headers: {
                    "Content-Type":
                        "application/json",
                    "Cache-Control":
                        "no-store"
                },

                body: JSON.stringify({

                    success: true,

                    applicationType:
                        "management",

                    application: {

                        type:
                            "management",

                        reference:
                            managementApplication
                                .management_application_reference,

                        fullName:
                            managementApplication
                                .full_name,

                        email:
                            managementApplication
                                .email,

                        category:
                            "Management",

                        requestedRole:
                            managementApplication
                                .requested_role,

                        status:
                            managementApplication
                                .application_status,

                        managementNote:
                            managementApplication
                                .management_note || "",

                        paymentStatus:
                            null,

                        paymentReference:
                            null,

                        paymentPaidAt:
                            null

                    }

                })

            };

        }


        /*
        ==================================================
        NOTHING FOUND
        ==================================================
        */

        return {
            statusCode: 404,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                error:
                    "Application reference not found."
            })
        };


    } catch (error) {

        console.error(
            "Application status error:",
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
                    "Something went wrong while checking your application."
            })
        };

    }

};