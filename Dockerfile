FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY sage /usr/local/bin/sage

ENTRYPOINT ["sage"]
