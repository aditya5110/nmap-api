FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod ./
COPY go.sum* ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/nmap-api ./cmd/api

FROM alpine:3.20

RUN apk add --no-cache ca-certificates nmap

WORKDIR /app
COPY --from=builder /bin/nmap-api /app/nmap-api

ENV APP_ENV=development
EXPOSE 8080

ENTRYPOINT ["/app/nmap-api"]
