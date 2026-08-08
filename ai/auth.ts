import axios from "axios";


let cachedToken: string | null = null;
let tokenExpiry = 0;

export async function getAccessToken(): Promise<string> {

    // Reuse token if it is still valid
    if (cachedToken && Date.now() < tokenExpiry) {
        return cachedToken;
    }

    const response = await axios.post(
        "https://iam.cloud.ibm.com/identity/token",

        new URLSearchParams({
            grant_type: "urn:ibm:params:oauth:grant-type:apikey",
            apikey: process.env.WATSONX_API_KEY!,
        }),

        {
            headers: {
                "Content-Type":
                    "application/x-www-form-urlencoded",
            },
        }
    );

    cachedToken = response.data.access_token;

    // Refresh 5 minutes before expiry
    tokenExpiry =
        Date.now() +
        (response.data.expires_in - 300) * 1000;

    return cachedToken!;
}