FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /boltlane ./cmd/boltlane

FROM alpine:3.21
RUN adduser -D -u 10001 boltlane
USER boltlane
COPY --from=build /boltlane /usr/local/bin/boltlane
COPY examples/quikrstuff-policy.json /etc/boltlane/quikrstuff-policy.json
EXPOSE 8080
ENTRYPOINT ["boltlane", "server"]
