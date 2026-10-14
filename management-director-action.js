exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({
        success: false,
        message: "Method not allowed."
      })
    };
  }

  try {
    const {
      action,
      applicationId,
      managementNote = ""
    } = JSON.parse(event.body || "{}");

    if (!action || !applicationId) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "Action and application ID are required."
        })
      };
    }

    if (!["approve", "reject"].includes(action)) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "Invalid management action."
        })
      };
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SECRET_KEY;
    const brevoApiKey = process.env.BREVO_API_KEY;

    if (!supabaseUrl || !supabaseKey) {
      throw new Error(
        "Supabase environment variables are missing."
      );
    }

    // Get the Director's Supabase access token
    const authHeader =
      event.headers.authorization ||
      event.headers.Authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message: "Director authentication required."
        })
      };
    }

    const accessToken =
      authHeader.replace("Bearer ", "").trim();

    // Verify the Supabase Auth token
    const userResponse = await fetch(
      `${supabaseUrl}/auth/v1/user`,
      {
        method: "GET",
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    if (!userResponse.ok) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message: "Invalid or expired Director session."
        })
      };
    }

    const directorUser = await userResponse.json();

    if (!directorUser.id) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message: "Director identity could not be verified."
        })
      };
    }

    // Check that this authenticated user is an active T-KEL Director
    const directorCheckResponse = await fetch(
      `${supabaseUrl}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(directorUser.id)}&select=user_id,full_name,active`,
      {
        method: "GET",
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`
        }
      }
    );

    if (!directorCheckResponse.ok) {
      throw new Error(
        "Unable to verify Director authorization."
      );
    }

    const directors =
      await directorCheckResponse.json();

    if (
      !directors.length ||
      directors[0].active !== true
    ) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          success: false,
          message:
            "You are not authorized as an active T-KEL Management Director."
        })
      };
    }

    // Get the management application
    const applicationResponse = await fetch(
      `${supabaseUrl}/rest/v1/management_applications?id=eq.${encodeURIComponent(applicationId)}&select=*`,
      {
        method: "GET",
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`
        }
      }
    );

    if (!applicationResponse.ok) {
      throw new Error(
        "Unable to retrieve the application."
      );
    }

    const applications =
      await applicationResponse.json();

    if (!applications.length) {
      return {
        statusCode: 404,
        body: JSON.stringify({
          success: false,
          message:
            "Management application not found."
        })
      };
    }

    const application = applications[0];

    // Prevent double decisions
    if (
      application.application_status !== "pending"
    ) {
      return {
        statusCode: 409,
        body: JSON.stringify({
          success: false,
          message:
            `This application has already been ${application.application_status}.`
        })
      };
    }

    const now = new Date().toISOString();

    // Reject application
    if (action === "reject") {
      const updateResponse = await fetch(
        `${supabaseUrl}/rest/v1/management_applications?id=eq.${encodeURIComponent(applicationId)}`,
        {
          method: "PATCH",
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal"
          },
          body: JSON.stringify({
            application_status: "rejected",
            management_note: managementNote,
            reviewed_by: directorUser.id,
            reviewed_at: now,
            updated_at: now
          })
        }
      );

      if (!updateResponse.ok) {
        throw new Error(
          "Failed to reject the application."
        );
      }

      return {
        statusCode: 200,
        body: JSON.stringify({
          success: true,
          message:
            "Management application rejected."
        })
      };
    }

    // Approve application
    if (action === "approve") {
      const updateResponse = await fetch(
        `${supabaseUrl}/rest/v1/management_applications?id=eq.${encodeURIComponent(applicationId)}`,
        {
          method: "PATCH",
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal"
          },
          body: JSON.stringify({
            application_status: "approved",
            management_note: managementNote,
            reviewed_by: directorUser.id,
            reviewed_at: now,
            updated_at: now
          })
        }
      );

      if (!updateResponse.ok) {
        throw new Error(
          "Failed to approve the application."
        );
      }

      /*
       * Send the Management Application Reference
       * to the applicant after successful approval.
       */
      if (brevoApiKey) {
        try {
          const emailResponse = await fetch(
            "https://api.brevo.com/v3/smtp/email",
            {
              method: "POST",
              headers: {
                "accept": "application/json",
                "api-key": brevoApiKey,
                "content-type": "application/json"
              },
              body: JSON.stringify({
                sender: {
                  name: "T-KEL Management",
                  email: "no-reply@t-kel.com"
                },
                to: [
                  {
                    email: application.email,
                    name: application.full_name
                  }
                ],
                subject:
                  "T-KEL Management Application Approved",
                htmlContent: `
                  <!DOCTYPE html>
                  <html>
                  <head>
                    <meta charset="UTF-8">
                    <title>T-KEL Management Application Approved</title>
                  </head>

                  <body style="
                    margin:0;
                    padding:0;
                    background:#f5f7fa;
                    font-family:Arial,sans-serif;
                    color:#222;
                  ">

                    <div style="
                      max-width:600px;
                      margin:30px auto;
                      background:#ffffff;
                      padding:30px;
                      border-radius:10px;
                    ">

                      <div style="
                        text-align:center;
                        margin-bottom:25px;
                      ">
                        <img
                          src="https://t-kel.com/logo.png"
                          alt="T-KEL Logo"
                          style="
                            max-width:180px;
                            height:auto;
                          "
                        >
                      </div>

                      <h2 style="
                        color:#007BFF;
                        text-align:center;
                      ">
                        Management Application Approved
                      </h2>

                      <p>
                        Dear ${String(
                          application.full_name || ""
                        )
                          .replace(/&/g, "&amp;")
                          .replace(/</g, "&lt;")
                          .replace(/>/g, "&gt;")
                          .replace(/"/g, "&quot;")
                          .replace(/'/g, "&#039;")},
                      </p>

                      <p>
                        Your application to join
                        <strong>T-KEL Management</strong>
                        has been approved.
                      </p>

                      <p>
                        Your
                        <strong>Management Application Reference</strong>
                        is:
                      </p>

                      <div style="
                        background:#f0f6ff;
                        border:1px solid #007BFF;
                        padding:18px;
                        text-align:center;
                        border-radius:8px;
                        margin:20px 0;
                      ">

                        <strong style="
                          font-size:22px;
                          color:#007BFF;
                          letter-spacing:1px;
                        ">
                          ${String(
                            application.management_application_reference || ""
                          )
                            .replace(/&/g, "&amp;")
                            .replace(/</g, "&lt;")
                            .replace(/>/g, "&gt;")
                            .replace(/"/g, "&quot;")
                            .replace(/'/g, "&#039;")}
                        </strong>

                      </div>

                      <p>
                        Please keep this reference safe.
                        You will need it during the next stage
                        of the T-KEL Management registration process.
                      </p>

                      <p>
                        Approval of the application does not yet
                        create your Management ID.
                        Your Management ID will be created by
                        an authorized T-KEL Management Director
                        after the required verification and registration
                        process.
                      </p>

                      <p>
                        Please follow any further instructions
                        provided by T-KEL Management.
                      </p>

                      <p>
                        Regards,<br>
                        <strong>T-KEL Management</strong><br>
                        Terriken Entertainment Limited
                      </p>

                      <p style="
                        margin-top:30px;
                        color:#666;
                        font-size:13px;
                        text-align:center;
                      ">
                        Stay Real, Stay kelz.
                      </p>

                    </div>

                  </body>
                  </html>
                `
              })
            }
          );

          if (!emailResponse.ok) {
            const emailError =
              await emailResponse.text();

            console.error(
              "Brevo approval email failed:",
              emailError
            );
          }

        } catch (emailError) {
          /*
           * The application has already been approved.
           * Do not reverse the approval because of an
           * email-delivery problem.
           */
          console.error(
            "Approval email error:",
            emailError
          );
        }
      } else {
        console.error(
          "BREVO_API_KEY is missing. Application was approved, but approval email was not sent."
        );
      }

      return {
    statusCode: 200,
    body: JSON.stringify({
        success: true,
        message:
            "Management application approved successfully."
    })
};
    }

  } catch (error) {
    console.error(
      "Management Director action error:",
      error
    );

    return {
      statusCode: 500,
      body: JSON.stringify({
        success: false,
        message:
          "An internal server error occurred."
      })
    };
  }
};