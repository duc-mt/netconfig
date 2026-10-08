# Multi-stage build for netconfig
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /app/netconfig ./cmd/netconfig

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/netconfig /app/netconfig

ENTRYPOINT ["/app/netconfig"]
