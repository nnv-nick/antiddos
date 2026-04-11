FROM golang:1.24-alpine3.21 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/legit-sender ./cmd/legit-sender
RUN CGO_ENABLED=0 go build -o /legit-sender ./cmd/legit-sender

FROM alpine:3.21
COPY --from=builder /legit-sender /legit-sender
EXPOSE 9155
ENTRYPOINT ["/legit-sender"]
