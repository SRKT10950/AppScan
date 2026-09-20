FROM python:3.12-slim-bookworm
ARG PMD_VERSION=7.17.0
ARG PMD_SHA256=440f6855769c1a651cebd735133cba188df077881af31bd923766b869482bebd
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless curl unzip ca-certificates \
    && curl --fail --location --retry 3 "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip" -o /tmp/pmd.zip \
    && echo "${PMD_SHA256}  /tmp/pmd.zip" | sha256sum -c - \
    && unzip -q /tmp/pmd.zip -d /opt && mv "/opt/pmd-bin-${PMD_VERSION}" /opt/pmd \
    && rm /tmp/pmd.zip && apt-get purge -y curl unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home appscan && mkdir /data && chown appscan:appscan /data \
    && pip install --no-cache-dir psycopg2-binary
WORKDIR /srv
COPY --chown=appscan:appscan app /srv/app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data PMD_BIN=/opt/pmd/bin/pmd JAVA_TOOL_OPTIONS=-Xmx768m
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3)"
CMD ["python", "-m", "app.server"]
