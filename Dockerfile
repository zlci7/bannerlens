FROM golang:1.25.3-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod ./
COPY . .
RUN go test ./... \
    && go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
    && go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM scratch AS server
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/server /app/server
COPY --chown=65532:65532 rules /app/rules
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/server"]
CMD ["-listen", ":8080", "-rules", "/app/rules/fingerprints.json"]

FROM scratch AS client
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/client /app/client
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/app/client"]
