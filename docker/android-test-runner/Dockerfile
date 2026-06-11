FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    android-tools-adb \
    netcat-openbsd \
    unzip \
    binutils \
    curl \
    python3-minimal \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Optional: uncomment to add Frida tooling (adds ~2min to build)
# RUN pip3 install --no-cache-dir frida-tools 2>/dev/null || true

COPY run-tests.sh /run-tests.sh
COPY test-android-docker.ps1 /scripts/test-android-docker.ps1
RUN chmod +x /run-tests.sh

ENTRYPOINT ["/run-tests.sh"]
