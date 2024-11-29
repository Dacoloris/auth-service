FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o app ./cmd/main.go


FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/app .
COPY --from=builder /app/.env .

ENV PORT=8080

EXPOSE 8080

CMD ["./app"]