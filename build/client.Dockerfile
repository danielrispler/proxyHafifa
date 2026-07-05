FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /svc ./cmd/client

FROM alpine:latest
RUN apk add --no-cache iproute2
COPY --from=build /svc /svc
COPY build/client-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
