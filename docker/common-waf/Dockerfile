FROM owasp/modsecurity-crs:nginx

COPY default.conf.template /etc/nginx/templates/conf.d/default.conf.template
COPY REQUEST-901-WEBXPLOIT.conf /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-WEBXPLOIT.conf

USER root
