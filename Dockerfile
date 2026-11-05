FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -o /airgapproof ./cmd/airgapproof
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/cenab/airgapproof"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /airgapproof /airgapproof
COPY LICENSE /LICENSE
COPY licenses /licenses
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/airgapproof"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
