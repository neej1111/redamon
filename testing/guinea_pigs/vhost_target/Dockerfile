FROM nginx:1.27-alpine

# The L4 half of the module lies about SNI, so the lab has to speak TLS. A
# self-signed cert is enough: the probe compares responses, it does not validate
# the chain. Generated at build time so no key material is ever committed.
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/certs \
 && openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -subj "/CN=vhostlab.test" \
      -addext "subjectAltName=DNS:vhostlab.test,DNS:admin.vhostlab.test,DNS:partner.cohost.test" \
      -keyout /etc/nginx/certs/lab.key \
      -out /etc/nginx/certs/lab.crt

COPY nginx/default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 443
