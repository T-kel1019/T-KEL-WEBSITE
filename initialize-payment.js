const crypto = require("crypto");

const PAYMENT_AMOUNT = 500000; // ₦5,000 in kobo

function generatePaymentReference() {
    return (
        "TKEL-P" +
        crypto.randomInt(100, 1000) +
        "Y" +
        crypto.randomBytes(16)
            .toString("hex")
            .toUpperCase() +
        "P"
    );
}

exports.handler = async function (event) {
    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "Method not allowed" })
        };
    }

    try {

        const body = JSON.parse(event.body || "{}");

        const email = String(body.email || "")
            .trim()
            .toLowerCase();

        const reference = String(body.reference || "")
            .trim()
            .toUpperCase();

        // fullName from the browser is NOT trusted.
        // We will get the real name from Supabase.

        if (!email || !reference) {
            return {
                statusCode: 400,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "Email and application reference are required."
                })
            };
        }

        const paystackSecret = process.env.PAYSTACK_SECRET_KEY;
        const supabaseUrl = process.env.SUPABASE_URL;
        const supabaseSecret = process.env.SUPABASE_SECRET_KEY;

        if (!paystackSecret || !supabaseUrl || !supabaseSecret) {
            console.error("Required environment variables are missing.");

            return {
                statusCode: 500,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "Payment system is not configured."
                })
            };
        }

        // --------------------------------------------------
        // 1. Find the application
        // --------------------------------------------------

        const applicationResponse = await fetch(
            supabaseUrl +
            "/rest/v1/applications" +
            "?application_reference=eq." +
            encodeURIComponent(reference) +
            "&select=id,full_name,email,category,application_status,payment_status,payment_reference,application_reference&limit=1",
            {
                method: "GET",
                headers: {
                    apikey: supabaseSecret,
                    Authorization: "Bearer " + supabaseSecret
                }
            }
        );

        if (!applicationResponse.ok) {
            console.error(
                "Unable to read application:",
                await applicationResponse.text()
            );

            return {
                statusCode: 500,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "Unable to verify your application."
                })
            };
        }

        const applications = await applicationResponse.json();

        if (!Array.isArray(applications) || applications.length === 0) {
            return {
                statusCode: 404,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "Application reference not found."
                })
            };
        }

        const application = applications[0];

        // --------------------------------------------------
        // 2. Confirm approval
        // --------------------------------------------------

        if (
            String(application.application_status || "")
                .toLowerCase() !== "approved"
        ) {
            return {
                statusCode: 403,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "This application has not been approved for payment."
                })
            };
        }

        // --------------------------------------------------
        // 3. Confirm email belongs to application
        // --------------------------------------------------

        if (
            String(application.email || "")
                .trim()
                .toLowerCase() !== email
        ) {
            return {
                statusCode: 403,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "The email address does not match this application."
                })
            };
        }

        // --------------------------------------------------
        // 4. Don't allow another payment after successful payment
        // --------------------------------------------------

        if (
            String(application.payment_status || "")
                .toLowerCase() === "paid"
        ) {
            return {
                statusCode: 409,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "This application has already been paid for.",
                    paid: true,
                    reference: application.application_reference
                })
            };
        }

        // --------------------------------------------------
        // 5. Generate a completely random Paystack reference
        // --------------------------------------------------

        let paymentReference = application.payment_reference;

if (!paymentReference) {

    paymentReference = generatePaymentReference();

            // --------------------------------------------------
            // 6. Atomically claim the reference
            // Prevents two simultaneous requests from replacing
            // each other's payment reference.
            // --------------------------------------------------

            const claimResponse = await fetch(
                supabaseUrl +
                "/rest/v1/applications?id=eq." +
                encodeURIComponent(application.id) +
                "&payment_reference=is.null",
                {
                    method: "PATCH",
                    headers: {
                        apikey: supabaseSecret,
                        Authorization: "Bearer " + supabaseSecret,
                        "Content-Type": "application/json",
                        Prefer: "return=representation"
                    },
                    body: JSON.stringify({
                        payment_reference: paymentReference,
                        payment_status: "pending"
                    })
                }
            );

            if (!claimResponse.ok) {

                console.error(
                    "Unable to claim payment reference:",
                    await claimResponse.text()
                );

                return {
                    statusCode: 500,
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        error: "Unable to prepare your payment."
                    })
                };
            }

            const claimedApplications = await claimResponse.json();

            // Another request may have created the reference first.
            if (
                !Array.isArray(claimedApplications) ||
                claimedApplications.length === 0
            ) {

                const latestResponse = await fetch(
                    supabaseUrl +
                    "/rest/v1/applications?id=eq." +
                    encodeURIComponent(application.id) +
                    "&select=payment_status,payment_reference&limit=1",
                    {
                        method: "GET",
                        headers: {
                            apikey: supabaseSecret,
                            Authorization: "Bearer " + supabaseSecret
                        }
                    }
                );

                if (!latestResponse.ok) {
                    return {
                        statusCode: 500,
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            error: "Unable to prepare your payment."
                        })
                    };
                }

                const latest = await latestResponse.json();

                if (
                    !Array.isArray(latest) ||
                    latest.length === 0 ||
                    !latest[0].payment_reference
                ) {
                    return {
                        statusCode: 500,
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            error: "Unable to prepare your payment."
                        })
                    };
                }

                paymentReference = latest[0].payment_reference;
            }

        } else {

            // Existing reference means a payment attempt already exists.
            // Keep using it instead of creating another reference.
            const status = String(
                application.payment_status || ""
            ).toLowerCase();

            if (status !== "pending") {

                // If it has a reference but isn't pending/paid,
                // reset it safely for a new payment attempt.
                paymentReference = generatePaymentReference();

                const resetResponse = await fetch(
                    supabaseUrl +
                    "/rest/v1/applications?id=eq." +
                    encodeURIComponent(application.id),
                    {
                        method: "PATCH",
                        headers: {
                            apikey: supabaseSecret,
                            Authorization: "Bearer " + supabaseSecret,
                            "Content-Type": "application/json",
                            Prefer: "return=minimal"
                        },
                        body: JSON.stringify({
                            payment_reference: paymentReference,
                            payment_status: "pending"
                        })
                    }
                );

                if (!resetResponse.ok) {
                    return {
                        statusCode: 500,
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            error: "Unable to prepare your payment."
                        })
                    };
                }
            }
        }

        // --------------------------------------------------
        // 7. Build callback URL
        // --------------------------------------------------

        const siteUrl =
            process.env.PUBLIC_SITE_URL ||
            process.env.URL ||
            "https://t-kel.com";

        const callbackUrl =
            new URL("/payment-success.html", siteUrl).toString();

             // --------------------------------------------------
        // 8. Initialize Paystack
        // --------------------------------------------------

        async function initializePaystack(referenceToUse) {

            return await fetch(
                "https://api.paystack.co/transaction/initialize",
                {
                    method: "POST",

                    headers: {
                        Authorization:
                            "Bearer " + paystackSecret,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        email: email,

                        amount:
                            PAYMENT_AMOUNT,

                        currency: "NGN",

                        reference:
                            referenceToUse,

                        callback_url:
                            callbackUrl,

                        metadata: {
                            full_name:
                                application.full_name,

                            application_reference:
                                application.application_reference
                        }

                    })
                }
            );
        }


        let paystackResponse =
            await initializePaystack(
                paymentReference
            );

        let paystackData =
            await paystackResponse.json();


        // --------------------------------------------------
        // 9. Handle duplicate Paystack reference
        // --------------------------------------------------

        const paystackMessage =
            String(
                paystackData.message || ""
            ).toLowerCase();


        if (
            !paystackResponse.ok &&
            paystackMessage.includes(
                "duplicate transaction reference"
            )
        ) {

            console.warn(
                "Paystack rejected existing reference. Generating a new reference."
            );


            // Generate a completely new reference
            paymentReference =
                generatePaymentReference();


            // Save the new reference in Supabase
            const updateReferenceResponse =
                await fetch(
                    supabaseUrl +
                    "/rest/v1/applications?id=eq." +
                    encodeURIComponent(
                        application.id
                    ),
                    {
                        method: "PATCH",

                        headers: {
                            apikey:
                                supabaseSecret,

                            Authorization:
                                "Bearer " +
                                supabaseSecret,

                            "Content-Type":
                                "application/json",

                            Prefer:
                                "return=minimal"
                        },

                        body: JSON.stringify({
                            payment_reference:
                                paymentReference,

                            payment_status:
                                "pending"
                        })
                    }
                );


            if (
                !updateReferenceResponse.ok
            ) {

                console.error(
                    "Unable to update payment reference:",
                    await updateReferenceResponse.text()
                );

                return {
                    statusCode: 500,

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        error:
                            "Unable to prepare a new payment reference."
                    })
                };
            }


            // Try Paystack again with the new reference
            paystackResponse =
                await initializePaystack(
                    paymentReference
                );

            paystackData =
                await paystackResponse.json();
        }


        // --------------------------------------------------
        // 10. Final Paystack check
        // --------------------------------------------------

        if (
            !paystackResponse.ok ||
            !paystackData.status
        ) {

            console.error(
                "Paystack initialization error:",
                paystackData
            );

            return {
                statusCode: 400,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    error:
                        paystackData.message ||
                        "Unable to initialize payment."
                })
            };
        }


        // --------------------------------------------------
        // 11. Return payment URL
        // --------------------------------------------------

        return {
            statusCode: 200,

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({

                success: true,

                authorization_url:
                    paystackData.data.authorization_url,

                reference:
                    paystackData.data.reference,

                application_reference:
                    application.application_reference

            })
        };
      
    } catch (error) {

        console.error(
            "Payment initialization error:",
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
                    "Something went wrong while starting payment."
            })
        };
    }
};