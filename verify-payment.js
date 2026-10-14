exports.handler = async function (event) {

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                error: "Method not allowed"
            })
        };
    }

    try {

        const body = JSON.parse(event.body || "{}");

        const paymentReference =
    String(body.reference || "")
        .trim()
        .toUpperCase();
        if (!paymentReference) {
            return {
                statusCode: 400,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    error: "Payment reference is required."
                })
            };
        }

        const paystackSecret =
            process.env.PAYSTACK_SECRET_KEY;

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const supabaseSecret =
            process.env.SUPABASE_SECRET_KEY;

        if (
            !paystackSecret ||
            !supabaseUrl ||
            !supabaseSecret
        ) {
            console.error(
                "Required environment variables are missing."
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Payment system is not configured."
                })
            };
        }

        // --------------------------------------------------
        // 1. Verify transaction directly with Paystack
        // --------------------------------------------------

        const paystackResponse = await fetch(
            "https://api.paystack.co/transaction/verify/" +
            encodeURIComponent(paymentReference),
            {
                method: "GET",
                headers: {
                    Authorization:
                        "Bearer " + paystackSecret,
                    "Content-Type":
                        "application/json"
                }
            }
        );

        let paystackData;

        try {
            paystackData =
                await paystackResponse.json();
        } catch (error) {

            console.error(
                "Invalid Paystack response."
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Invalid response from payment provider."
                })
            };
        }

        if (
            !paystackResponse.ok ||
            !paystackData.status ||
            !paystackData.data
        ) {

            console.error(
                "Paystack verification failed:",
                paystackData
            );

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        paystackData.message ||
                        "Unable to verify payment."
                })
            };
        }

        const transaction =
            paystackData.data;

        // --------------------------------------------------
        // 2. Check Paystack transaction status
        // --------------------------------------------------

        if (
            String(transaction.status || "")
                .toLowerCase() !== "success"
        ) {

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        "Payment has not been successfully completed."
                })
            };
        }

        // --------------------------------------------------
        // 3. Check transaction reference
        // --------------------------------------------------

        if (
            String(transaction.reference || "") !==
            paymentReference
        ) {

            console.error(
                "Payment reference mismatch."
            );

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        "Payment reference verification failed."
                })
            };
        }

        // --------------------------------------------------
        // 4. Check payment amount
        // ₦5,000 = 500,000 kobo
        // --------------------------------------------------

        if (
            Number(transaction.amount) !== 500000
        ) {

            console.error(
                "Incorrect payment amount:",
                transaction.amount
            );

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        "The payment amount does not match the required application fee."
                })
            };
        }
        // --------------------------------------------------
        // 4b. Check payment currency
        // --------------------------------------------------

        if (
            String(transaction.currency || "").toUpperCase() !== "NGN"
        ) {

    console.error(
        "Incorrect payment currency:",
        transaction.currency
    );

    return {
        statusCode: 400,
        headers: {
            "Content-Type":
                "application/json"
        },
        body: JSON.stringify({
            success: false,
            paid: false,
            error:
                "The payment currency is not valid for this application."
        })
    };
}
        // --------------------------------------------------
        // 5. Get application reference from metadata
        // --------------------------------------------------

        let metadata =
            transaction.metadata || {};

        // Some payment-provider responses can return
        // metadata as a JSON string.
        if (typeof metadata === "string") {
            try {
                metadata = JSON.parse(metadata);
            } catch (error) {
                metadata = {};
            }
        }

        const applicationReference =
            String(
                metadata.application_reference || ""
            )
            .trim()
            .toUpperCase();

        if (!applicationReference) {

            console.error(
                "Missing application_reference metadata."
            );

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This payment is not linked to a T-KEL application."
                })
            };
        }

        // --------------------------------------------------
        // 6. Find the application
        // --------------------------------------------------

        const applicationResponse =
            await fetch(
                supabaseUrl +
                "/rest/v1/applications" +
                "?application_reference=eq." +
                encodeURIComponent(applicationReference) +
                "&select=" +
                "id,application_reference,full_name,email," +
                "category,application_status,payment_status," +
                "payment_reference" +
                "&limit=1",
                {
                    method: "GET",
                    headers: {
                        apikey:
                            supabaseSecret,
                        Authorization:
                            "Bearer " +
                            supabaseSecret
                    }
                }
            );

        if (!applicationResponse.ok) {

            console.error(
                "Unable to find application:",
                await applicationResponse.text()
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Unable to connect this payment to your application."
                })
            };
        }

        const applications =
            await applicationResponse.json();

        if (
            !Array.isArray(applications) ||
            applications.length === 0
        ) {

            return {
                statusCode: 404,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "The T-KEL application linked to this payment was not found."
                })
            };
        }

        const application =
            applications[0];

        // --------------------------------------------------
        // 7. Make sure the payment reference belongs
        // to this application
        // --------------------------------------------------

        if (
            String(application.payment_reference || "") !==
            paymentReference
        ) {

            console.error(
                "Stored payment reference does not match Paystack reference.",
                {
                    stored:
                        application.payment_reference,
                    paystack:
                        paymentReference
                }
            );

            return {
                statusCode: 400,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        "This payment does not match the payment prepared for this application."
                })
            };
        }

        // --------------------------------------------------
        // 8. Confirm application is approved
        // --------------------------------------------------

        if (
            String(application.application_status || "")
                .toLowerCase() !== "approved"
        ) {

            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "This application is not approved for payment."
                })
            };
        }

        // --------------------------------------------------
        // 9. Confirm Paystack customer email matches
        // application email
        // --------------------------------------------------

        const paystackEmail =
            String(
                transaction.customer?.email || ""
            )
            .trim()
            .toLowerCase();

        const applicationEmail =
            String(
                application.email || ""
            )
            .trim()
            .toLowerCase();

        if (
            !paystackEmail ||
            !applicationEmail ||
            paystackEmail !== applicationEmail
        ) {

            console.error(
                "Payment email does not match application email.",
                {
                    paystackEmail,
                    applicationEmail
                }
            );

            return {
                statusCode: 403,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    success: false,
                    paid: false,
                    error:
                        "The payment email does not match the email on this application."
                })
            };
        }

        // --------------------------------------------------
        // 10. Save payment as PAID
        // --------------------------------------------------

        const paidAt =
            new Date().toISOString();

        const updateResponse =
            await fetch(
                supabaseUrl +
                "/rest/v1/applications?id=eq." +
                encodeURIComponent(application.id),
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
                        payment_status:
                            "paid",

                        payment_reference:
                            paymentReference,

                        payment_paid_at:
                            paidAt
                    })
                }
            );

        if (!updateResponse.ok) {

            const updateError =
                await updateResponse.text();

            console.error(
                "Unable to save payment:",
                updateError
            );

            return {
                statusCode: 500,
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    error:
                        "Payment was verified, but we could not update your T-KEL application. Please contact T-KEL Management."
                })
            };
        }

        // --------------------------------------------------
        // 11. Success
        // --------------------------------------------------

        return {
            statusCode: 200,
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({

                success: true,

                paid: true,

                paymentReference:
                    paymentReference,

                applicationReference:
                    applicationReference,

                amount:
                    transaction.amount,

                email:
                    application.email,

                fullName:
                    application.full_name,

                category:
                    application.category
            })
        };

    } catch (error) {

        console.error(
            "Payment verification error:",
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
                    "Something went wrong while verifying payment."
            })
        };
    }
};