#!/bin/sh
# Render the nginx config from its template, substituting ONLY $API_KEY.
# An explicit variable list matters: a bare `envsubst` would also replace
# nginx's own $host / $uri / $remote_addr variables with empty strings.
# envsubst ships with the nginx:1.27-alpine image.
set -e
envsubst '$API_KEY' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf
exec "$@"
