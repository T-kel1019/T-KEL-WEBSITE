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
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl || !supabaseKey) {
      throw new Error(
        "Supabase environment variables are missing."
      );
    }

    /*
     * Get the Director's login token.
     */
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


    /*
     * Verify the logged-in Supabase user.
     */
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

    const user = await userResponse.json();

    if (!user.id) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message: "Director identity could not be verified."
        })
      };
    }


    /*
     * Confirm that the user is an ACTIVE
     * T-KEL Management Director.
     */
    const directorResponse = await fetch(
      `${supabaseUrl}/rest/v1/management_directors?user_id=eq.${encodeURIComponent(user.id)}&select=user_id,full_name,active`,
      {
        method: "GET",
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`
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
     * Get pending Management applications.
     */
    const applicationsResponse = await fetch(
      `${supabaseUrl}/rest/v1/management_applications?application_status=eq.pending&select=id,management_application_reference,full_name,email,phone,location,date_of_birth,gender,requested_role,experience,photo_url,application_status,management_note,created_at&order=created_at.desc`,
      {
        method: "GET",
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`
        }
      }
    );

    if (!applicationsResponse.ok) {
      throw new Error(
        "Unable to retrieve Management applications."
      );
    }

    const applications =
      await applicationsResponse.json();


    /*
     * Return only the applications the Director
     * is authorized to see.
     */
    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        applications
      })
    };

  } catch (error) {

    console.error(
      "Management Director applications error:",
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