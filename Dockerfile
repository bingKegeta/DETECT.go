FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main cmd/api/main.go

FROM alpine:3.20.1 AS prod

WORKDIR /app

COPY --from=build /app/main /app/main

COPY .env .env
COPY HMM.py /app/HMM.py

RUN apk update && apk add --no-cache python3 py3-pip

EXPOSE ${PORT}

CMD ["./main"]
