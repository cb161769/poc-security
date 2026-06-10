FROM node:22-bookworm

# Install JDK 21 via Eclipse Temurin (Adoptium) — Bookworm main repo only has JDK 17
RUN apt-get update && apt-get install -y --no-install-recommends wget apt-transport-https gnupg unzip curl && \
    wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
        | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb bookworm main" \
        | tee /etc/apt/sources.list.d/adoptium.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends temurin-21-jdk && \
    rm -rf /var/lib/apt/lists/*

# Detect real JAVA_HOME and store it so the entrypoint can source it
RUN echo "JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))" > /etc/java_home.env

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Android command-line tools (cmdline-tools 13.0)
RUN mkdir -p $ANDROID_HOME/cmdline-tools && \
    curl -sSL "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" \
         -o /tmp/ct.zip && \
    unzip -q /tmp/ct.zip -d /tmp/ct && \
    mv /tmp/ct/cmdline-tools $ANDROID_HOME/cmdline-tools/latest && \
    rm -rf /tmp/ct.zip /tmp/ct

RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager \
        "platform-tools" \
        "platforms;android-36" \
        "build-tools;34.0.0"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
