FROM golang:1.26-alpine AS build
WORKDIR /app
RUN apk add --no-cache libpcap-dev gcc musl-dev
ENV CGO_ENABLED=1
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /svc ./cmd/proxy

FROM alpine:latest
RUN apk add --no-cache libpcap iptables
COPY --from=build /svc /svc
COPY build/proxy-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
