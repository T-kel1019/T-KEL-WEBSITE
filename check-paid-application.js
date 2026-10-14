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
            JSON.parse(
                event.body || "{}"
            );


        /*
        ==========================================
        GET PAYMENT REFERENCE
        ==========================================
        */

        const paymentReference =
    String(
        body.reference || ""
    ).trim().toUpperCase();

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


        /*
        ==========================================
        SUPABASE CONFIGURATION
        ==========================================
        */

        const supabaseUrl =
            process.env.SUPABASE_URL;


        const supabaseSecret =
            process.env.SUPABASE_SECRET_KEY;


        if (
            !supabaseUrl ||
            !supabaseSecret
        ) {

            console.error(
                "Supabase environment variables are missing."
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
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
                supabaseSecret
            );


        /*
        ==========================================
        FIND APPLICATION USING PAYMENT REFERENCE
        ==========================================
        */

        const {
            data,
            error
        } =
            await supabase
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


        if (error) {

            console.error(
                "Supabase error:",
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
                        "Unable to verify your payment."
                })
            };

        }


        /*
        ==========================================
        APPLICATION NOT FOUND
        ==========================================
        */

        if (!data) {

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


        /*
        ==========================================
        CONFIRM APPLICATION APPROVED
        ==========================================
        */

        if (
            String(
                data.application_status || ""
            ).toLowerCase() !==
            "approved"
        ) {

            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This application is not approved."
                })
            };

        }


        /*
        ==========================================
        CONFIRM PAYMENT COMPLETED
        ==========================================
        */

        if (
            String(
                data.payment_status || ""
            ).toLowerCase() !==
            "paid"
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


        /*
        ==========================================
        CHECK WHETHER FORM WAS ALREADY SUBMITTED
        ==========================================
        */

        const {
            data: existingForm,
            error: formError
        } =
            await supabase
                .from("application_forms")
                .select("id")
                .eq(
                    "application_id",
                    data.id
                )
                .maybeSingle();


        if (formError) {

            console.error(
                "Application form lookup error:",
                formError
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


        /*
        ==========================================
        EVERYTHING VERIFIED
        ==========================================
        */

        return {
            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body:
                JSON.stringify({

                    success:
                        true,

                    paid:
                        true,

                    formSubmitted:
                        !!existingForm,

                    application: {

                        id:
                            data.id,

                        reference:
                            data.application_reference,

                        fullName:
                            data.full_name,

                        email:
                            data.email,

                        phone:
                            data.phone,

                        dateOfBirth:
                            data.date_of_birth,

                        gender:
                            data.gender,

                        category:
                            data.category,

                        experience:
                            data.experience

                    }

                })

        };


    } catch (error) {

        console.error(
            "Check paid application error:",
            error
        );


        return {
            statusCode: 500,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body:
                JSON.stringify({
                    error:
                        "Something went wrong while checking your application."
                })

        };

    }

};