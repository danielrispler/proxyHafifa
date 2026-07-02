FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /svc ./cmd/server

FROM alpine:latest
COPY --from=build /svc /svc
ENTRYPOINT ["/svc"]
