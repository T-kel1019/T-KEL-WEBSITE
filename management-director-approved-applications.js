exports.handler = async (event) => {

  if (event.httpMethod !== "GET") {
    return {
      statusCode: 405,
      body: JSON.stringify({
        success: false,
        message: "Method not allowed."
      })
    };
  }

  try {

    const supabaseUrl =
      process.env.SUPABASE_URL;

    const supabaseKey =
      process.env.SUPABASE_SECRET_KEY;


    if (!supabaseUrl || !supabaseKey) {
      throw new Error(
        "Supabase environment variables are missing."
      );
    }


    /*
     * Get Director access token.
     */
    const authHeader =
      event.headers.authorization ||
      event.headers.Authorization;


    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message:
            "Management Director authentication required."
        })
      };
    }


    const accessToken =
      authHeader.replace("Bearer ", "").trim();


    /*
     * Verify the Supabase user.
     */
    const userResponse =
      await fetch(
        `${supabaseUrl}/auth/v1/user`,
        {
          method: "GET",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${accessToken}`
          }
        }
      );


    if (!userResponse.ok) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message:
            "Invalid or expired Director session."
        })
      };
    }


    const directorUser =
      await userResponse.json();


    if (!directorUser.id) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message:
            "Director identity could not be verified."
        })
      };
    }


    /*
     * Confirm active Management Director.
     */
    const directorResponse =
      await fetch(
        `${supabaseUrl}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(directorUser.id)}&select=user_id,full_name,active`,
        {
          method: "GET",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`
          }
        }
      );


    if (!directorResponse.ok) {
      throw new Error(
        "Unable to verify Director authorization."
      );
    }


    const directors =
      await directorResponse.json();


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


    /*
     * Get approved applications that have
     * not yet been registered as Management accounts.
     */
    const applicationsResponse =
      await fetch(
        `${supabaseUrl}/rest/v1/management_applications?application_status=eq.approved&select=id,management_application_reference,full_name,email,phone,location,date_of_birth,gender,requested_role,experience,photo_url,application_status,management_note,created_at&order=reviewed_at.desc`,
        {
          method: "GET",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`
          }
        }
      );


    if (!applicationsResponse.ok) {
      throw new Error(
        "Unable to retrieve approved applications."
      );
    }


    const applications =
      await applicationsResponse.json();


    /*
     * Find which approved applications already
     * have Management accounts.
     */
    const accountsResponse =
      await fetch(
        `${supabaseUrl}/rest/v1/management_accounts?select=management_application_id`,
        {
          method: "GET",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`
          }
        }
      );


    if (!accountsResponse.ok) {
      throw new Error(
        "Unable to check Management accounts."
      );
    }


    const accounts =
      await accountsResponse.json();


    const registeredApplicationIds =
      new Set(
        accounts
          .map(
            account =>
              account.management_application_id
          )
          .filter(Boolean)
      );


    /*
     * Remove applications that already have
     * Management accounts.
     */
    const availableApplications =
      applications.filter(
        application =>
          !registeredApplicationIds.has(
            application.id
          )
      );


    return {
      statusCode: 200,

      body: JSON.stringify({
        success: true,
        applications:
          availableApplications
      })
    };


  } catch (error) {

    console.error(
      "Approved Management applications error:",
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