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
        const {
            fullName,
            email,
            applicationReference,
            category,
            managementNote
        } = JSON.parse(event.body || "{}");

        if (!email) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Applicant email is required."
                })
            };
        }

        if (!process.env.BREVO_API_KEY) {
            console.error("BREVO_API_KEY is missing.");

            return {
                statusCode: 500,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Email service is not configured."
                })
            };
        }

        const safeName = String(fullName || "Applicant");
        const safeCategory = String(
            category || "T-KEL Application"
        );
        const safeReference = String(
            applicationReference || "N/A"
        );
        const safeNote = String(managementNote || "");

        const brevoResponse = await fetch(
            "https://api.brevo.com/v3/smtp/email",
            {
                method: "POST",
                headers: {
                    accept: "application/json",
                    "api-key": process.env.BREVO_API_KEY,
                    "content-type": "application/json"
                },
                body: JSON.stringify({
                    sender: {
                        name: "T-KEL",
                        email: "no-reply@t-kel.com"
                    },

                    to: [
                        {
                            email: email,
                            name: safeName
                        }
                    ],

                    subject: "🎉 T-KEL Application Approved",

                    htmlContent: `
                        <div style="font-family:Arial,sans-serif;line-height:1.6;max-width:600px;margin:auto;">

                            <img
    src="https://t-kel.com/T-KEL%20logo.png"
    alt="T-KEL Logo"
    width="180"
    style="display:block;width:180px;max-width:100%;height:auto;margin:0 auto 20px;"
>

                            <h2>
                                🎉 Your T-KEL Application Has Been Approved
                            </h2>

                            <p>
                                Hello ${safeName},
                            </p>

                            <p>
                                Congratulations! Your application has been
                                approved by T-KEL Management.
                            </p>

                            <p>
                                <strong>Application Category:</strong>
                                ${safeCategory}
                            </p>

                            <p>
                                <strong>Application Reference:</strong>
                                ${safeReference}
                            </p>

                            <p>
                                You may now proceed to the next step of your
                                application on the T-KEL website.
                            </p>

                            ${
                                safeCategory === "Music Artist"
                                    ? `
                                        <p>
                                            For T-KEL Distribution, visit the
                                            Distribution section of our website
                                            and create your Artist Account using
                                            the same email address used for
                                            your application.
                                        </p>
                                    `
                                    : ""
                            }

                            ${
                                safeNote
                                    ? `
                                        <p>
                                            <strong>
                                                Message from T-KEL Management:
                                            </strong>
                                        </p>

                                        <p>
                                            ${safeNote}
                                        </p>
                                    `
                                    : ""
                            }

                            <p>
                                <strong>Stay Real, Stay kelz.</strong>
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

        const responseText = await brevoResponse.text();

        let result = {};

        try {
            result = responseText
                ? JSON.parse(responseText)
                : {};
        } catch (error) {
            console.error(
                "Brevo returned non-JSON response:",
                responseText
            );

            return {
                statusCode: 502,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Brevo returned an invalid response.",
                    brevoStatus: brevoResponse.status
                })
            };
        }

        if (!brevoResponse.ok) {
            console.error("Brevo error:", {
                status: brevoResponse.status,
                result
            });

            return {
                statusCode: 502,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error: "Brevo rejected the email.",
                    brevoStatus: brevoResponse.status,
                    details: result
                })
            };
        }

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                success: true,
                message: "Approval email sent successfully.",
                messageId: result.messageId || null
            })
        };

    } catch (error) {
        console.error("Send application email error:", error);

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error:
                    error.message ||
                    "Unable to send approval email."
            })
        };
    }
};