# Multi-arch image (arm64 for the RB5009). Built and pushed to GHCR by
# .github/workflows/erpwifi-image.yml; build locally with:
#   docker buildx build --platform linux/arm64 -t erpwifi:arm64 --output type=docker,dest=erpwifi-arm64.tar .
FROM python:3.12-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache
ENV ERPWIFI_CONFIG=/data/config.toml PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 1812/udp 1813/udp 8080/tcp
CMD ["erpwifi", "run"]
