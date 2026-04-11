FROM golang:1.24-alpine3.21 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/attacker ./cmd/attacker
RUN CGO_ENABLED=0 go build -o /attacker ./cmd/attacker

FROM alpine:3.21
COPY --from=builder /attacker /attacker
EXPOSE 9156
ENTRYPOINT ["/attacker"]
