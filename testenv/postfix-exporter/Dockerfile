FROM golang:1.24-alpine3.21 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/postfix-exporter ./cmd/postfix-exporter
RUN CGO_ENABLED=0 go build -o /postfix-exporter ./cmd/postfix-exporter

FROM alpine:3.21
COPY --from=builder /postfix-exporter /postfix-exporter
EXPOSE 9154
ENTRYPOINT ["/postfix-exporter"]
