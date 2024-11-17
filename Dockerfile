FROM alpine:latest as build
RUN apk add build-base
WORKDIR /tmp
COPY . ./
RUN make

FROM alpine:latest
COPY --from=build /tmp/wsproxy /usr/local/bin/wsproxy

CMD ["wsproxy"]