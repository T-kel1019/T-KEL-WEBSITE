exports.handler = async function (event) {

    const query =
        event.queryStringParameters?.q?.trim();

    if (!query) {
        return {
            statusCode: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "Search query is required"
            })
        };
    }

    const apiKey =
        process.env.YOUTUBE_API_KEY;

    const channelId =
        "UC3GgppJKjkTiuTUMHMq3BaQ";

    if (!apiKey) {

        console.error(
            "YOUTUBE_API_KEY is missing."
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error: "YouTube search is temporarily unavailable."
            })
        };
    }

    try {

        const searchUrl =
            "https://www.googleapis.com/youtube/v3/search" +
            "?part=snippet" +
            "&channelId=" +
            encodeURIComponent(channelId) +
            "&type=video" +
            "&maxResults=50" +
            "&q=" +
            encodeURIComponent(query) +
            "&key=" +
            encodeURIComponent(apiKey);

        const searchResponse =
            await fetch(searchUrl);

        const searchData =
            await searchResponse.json();

        if (!searchResponse.ok) {

            console.error(
                "YouTube API error:",
                searchData
            );

            return {
                statusCode: 502,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    error:
                        "YouTube search is temporarily unavailable."
                })
            };
        }

        if (
            searchData.items &&
            searchData.items.length > 0
        ) {

            const video =
                searchData.items.find(
                    item =>
                        item.id &&
                        item.id.videoId
                );

            if (video) {

                return {
                    statusCode: 200,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        found: true,
                        videoId:
                            video.id.videoId,
                        title:
                            video.snippet?.title || "",
                        description:
                            video.snippet?.description || "",
                        thumbnail:
                            video.snippet?.thumbnails?.high?.url ||
                            video.snippet?.thumbnails?.medium?.url ||
                            video.snippet?.thumbnails?.default?.url ||
                            ""
                    })
                };
            }
        }

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                found: false
            })
        };

    } catch (error) {

        console.error(
            "YouTube search failed:",
            error
        );

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                error:
                    "YouTube search is temporarily unavailable."
            })
        };
    }
};