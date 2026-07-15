FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/praetor-secrets ./cmd/praetor-secrets
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/praetor-audit-sink ./cmd/praetor-audit-sink

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN addgroup -S -g 10001 praetor-secrets \
    && adduser -S -D -H -u 10001 -G praetor-secrets praetor-secrets \
    && apk add --no-cache ca-certificates
COPY --from=builder /out/praetor-secrets /usr/local/bin/praetor-secrets
COPY --from=builder /out/praetor-audit-sink /usr/local/bin/praetor-audit-sink
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/praetor-secrets"]
