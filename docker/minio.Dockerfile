# Add a tiny static HTTP probe so MinIO has a reliable Compose health check
# without assuming curl, wget, or a shell is present in the upstream image.
FROM busybox:1.37.0 AS health_probe
FROM minio/minio:RELEASE.2025-04-22T22-12-26Z

COPY --from=health_probe /bin/busybox /busybox
