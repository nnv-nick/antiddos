FROM golang:1.24-alpine3.21 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/antiddos ./cmd/antiddos
RUN CGO_ENABLED=0 go build -o /antiddos ./cmd/antiddos

FROM alpine:3.21
COPY --from=builder /antiddos /antiddos
ENTRYPOINT ["/antiddos"]
