FROM golang:1.23-alpine AS builder
RUN apk add --no-cache libpcap-dev gcc libc-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o sniffer main.go

FROM alpine:latest
RUN apk add --no-cache libpcap
WORKDIR /root/
COPY --from=builder /app/sniffer .
EXPOSE 8080
CMD ["./sniffer"]
