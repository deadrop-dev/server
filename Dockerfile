# Multi-stage build: static Go binary on a scratch base (~10 MB image).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /deadrop-server ./cmd/deadrop-server

FROM scratch
COPY --from=build /deadrop-server /deadrop-server
ENV DEADROP_STORAGE_PATH=/data/deadrop.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/deadrop-server"]
