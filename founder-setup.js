const crypto = require("crypto");

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function generateManagementId() {
  const characters =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  let id = "TK";

  for (let i = 0; i < 6; i++) {
    id += characters[
      crypto.randomInt(0, characters.length)
    ];
  }

  return id;
}

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(first, second);
}

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
      setupKey,
      fullName,
      password
    } = JSON.parse(event.body || "{}");


    if (!setupKey || !fullName || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "All Founder setup fields are required."
        })
      };
    }


    if (fullName.trim().length < 2) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "Please enter a valid Founder name."
        })
      };
    }


    if (password.length < 8) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message:
            "Founder password must be at least 8 characters."
        })
      };
    }


    const supabaseUrl =
      process.env.SUPABASE_URL;

    const supabaseKey =
      process.env.SUPABASE_SECRET_KEY;

    const founderSetupKey =
      process.env.FOUNDER_SETUP_KEY;


    if (
      !supabaseUrl ||
      !supabaseKey ||
      !founderSetupKey
    ) {
      throw new Error(
        "Required environment variables are missing."
      );
    }


    /*
     * Verify the secret Founder Setup Key.
     *
     * The actual key is stored in Netlify
     * environment variables and is NEVER
     * placed inside the public HTML.
     */

    if (!safeCompare(setupKey, founderSetupKey)) {

      return {
        statusCode: 401,
        body: JSON.stringify({
          success: false,
          message: "Invalid Founder Setup Key."
        })
      };
    }


    /*
     * Check whether a Founder already exists.
     */

    const founderResponse = await fetch(
      `${supabaseUrl}/rest/v1/management_accounts` +
      `?assigned_role=eq.Founder` +
      `&select=id,management_id,account_status` +
      `&limit=1`,
      {
        method: "GET",

        headers: {
          apikey: supabaseKey,
          Authorization:
            `Bearer ${supabaseKey}`
        }
      }
    );


    if (!founderResponse.ok) {
      throw new Error(
        "Unable to check Founder account."
      );
    }


    const existingFounders =
      await founderResponse.json();


    if (existingFounders.length > 0) {

      return {
        statusCode: 409,
        body: JSON.stringify({
          success: false,
          message:
            "A Founder account already exists. Please use Founder Access to log in."
        })
      };
    }


    /*
     * Generate a unique Management ID.
     */

    let managementId;
    let idExists = true;

    for (let attempt = 0; attempt < 10; attempt++) {

      managementId =
        generateManagementId();


      const idResponse = await fetch(
        `${supabaseUrl}/rest/v1/management_accounts` +
        `?management_id=eq.${encodeURIComponent(
          managementId
        )}` +
        `&select=id` +
        `&limit=1`,
        {
          method: "GET",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`
          }
        }
      );


      if (!idResponse.ok) {
        throw new Error(
          "Unable to verify Management ID."
        );
      }


      const idResults =
        await idResponse.json();

      idExists =
        idResults.length > 0;


      if (!idExists) {
        break;
      }
    }


    if (idExists) {
      throw new Error(
        "Unable to generate a unique Management ID."
      );
    }


    /*
     * Securely hash the Founder password.
     */

    const salt =
      crypto.randomBytes(16).toString("hex");

    const derivedKey =
      await scryptAsync(
        password,
        salt
      );

    const passwordHash =
      `scrypt:${salt}:${derivedKey.toString("hex")}`;


    /*
     * Create the Founder account.
     */

    const accountResponse =
      await fetch(
        `${supabaseUrl}/rest/v1/management_accounts`,
        {
          method: "POST",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`,
            "Content-Type":
              "application/json",
            Prefer:
              "return=representation"
          },

          body: JSON.stringify({
            management_id:
              managementId,

            management_application_id:
              null,

            full_name:
              fullName.trim(),

            email:
              null,

            phone:
              null,

            assigned_role:
              "Founder",

            department:
              "Executive Management",

            password_hash:
              passwordHash,

            account_status:
              "ACTIVE",

            created_by:
              null,

            created_at:
              new Date().toISOString(),

            updated_at:
              new Date().toISOString(),

            last_login_at:
              null,

            removed_at:
              null
            
          })
        }
      );


    if (!accountResponse.ok) {

    const errorText =
      await accountResponse.text();

    console.error(
      "Founder account creation error:",
      errorText
    );

    throw new Error(
      `Founder account creation failed: ${errorText}`
    );
}


    const createdAccounts =
      await accountResponse.json();


    if (!createdAccounts.length) {
      throw new Error(
        "Founder account was not returned."
      );
    }


    const account =
      createdAccounts[0];


    /*
     * Create secure management session.
     */

    const sessionToken =
      crypto.randomBytes(48).toString("hex");

    const tokenHash =
      hashToken(sessionToken);

    const expiresAt =
      new Date(
        Date.now() +
        7 * 24 * 60 * 60 * 1000
      ).toISOString();


    const sessionResponse =
      await fetch(
        `${supabaseUrl}/rest/v1/management_sessions`,
        {
          method: "POST",

          headers: {
            apikey: supabaseKey,
            Authorization:
              `Bearer ${supabaseKey}`,
            "Content-Type":
              "application/json",
            Prefer:
              "return=minimal"
          },

          body: JSON.stringify({
            management_account_id:
              account.id,

            token_hash:
              tokenHash,

            expires_at:
              expiresAt
          })
        }
      );


if (!sessionResponse.ok) {

    const errorText =
      await sessionResponse.text();

    console.error(
      "Founder session creation error:",
      errorText
    );

    throw new Error(
      `Founder session creation failed: ${errorText}`
    );
}


    /*
     * Return the secure session cookie.
     */

    return {
      statusCode: 200,

      headers: {
        "Content-Type":
          "application/json",

        "Set-Cookie":
          `t-kel_management_session=${sessionToken}; ` +
          `HttpOnly; ` +
          `Secure; ` +
          `SameSite=Lax; ` +
          `Path=/; ` +
          `Max-Age=604800`
      },

      body: JSON.stringify({
        success: true,

        message:
          "Founder access created successfully. Opening the Management Dashboard...",

        management: {
          managementId:
            account.management_id,

          fullName:
            account.full_name,

          assignedRole:
            account.assigned_role,

          department:
            account.department,

          accountStatus:
            account.account_status
        }
      })
    };

      } catch (error) {

    console.error(
      "Founder setup error:",
      error
    );

    return {
      statusCode: 500,

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        success: false,
        message:
          error.message ||
          "An internal server error occurred while setting up Founder access."
      })
    };
  }
};