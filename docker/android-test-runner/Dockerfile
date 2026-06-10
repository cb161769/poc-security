FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    android-tools-adb \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY run-tests.sh /run-tests.sh
COPY test-android-docker.ps1 /scripts/test-android-docker.ps1
RUN chmod +x /run-tests.sh

ENTRYPOINT ["/run-tests.sh"]
