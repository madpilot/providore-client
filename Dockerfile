FROM --platform=$BUILDPLATFORM golang:1.14 as builder

ARG TARGETARCH

WORKDIR /app
COPY src /app
RUN GOOS=linux GOARCH=$TARGETARCH go build -a -o output/providore-client client.go

FROM alpine:latest
WORKDIR /usr/local/bin
RUN mkdir -p /usr/share/providore
COPY --from=builder /app/output/providore-client .
CMD /usr/local/bin/providore-client
