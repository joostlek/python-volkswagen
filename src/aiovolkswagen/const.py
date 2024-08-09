"""Constants for Volkswagen We Connect."""

X_APP_VERSION = "1.4.0"
X_APP_NAME = "SEATConnect"
USER_AGENT = "okhttp/3.10.0"
APP_URI = "cupraconnect://identity-kit/login"

CLIENT_ID = "30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com"

HEADERS_AUTH = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "x-requested-with": X_APP_NAME,
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}
