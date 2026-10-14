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
      throw new Error("Supabase environment variables are missing.");
    }

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
     * Verify the Supabase user session.
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
     * Check whether this user is an active
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
        "Unable to verify Management Director."
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

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        director: {
          user_id: directors[0].user_id,
          full_name: directors[0].full_name,
          active: directors[0].active
        }
      })
    };

  } catch (error) {

    console.error(
      "Management Director session error:",
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