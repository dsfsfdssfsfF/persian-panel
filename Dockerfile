FROM ghcr.io/mhsanaei/3x-ui:latest

# nginx + envsubst (gettext) to multiplex the panel, subscription service,
# and the 9 inbound slots behind the single public port Railway gives us
RUN apk add --no-cache nginx gettext bash

# Railway's sandbox does not grant NET_ADMIN/NET_RAW, which the bundled
# fail2ban needs to enforce IP bans — leave it off so the panel starts cleanly
ENV XUI_ENABLE_FAIL2BAN="false"

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Railway injects PORT at runtime; nginx listens on it, x-ui and the
# inbounds stay on internal-only ports (2053 / 2096 / 8081-8089) behind it
EXPOSE 8080

ENTRYPOINT ["/start.sh"]
