FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    unzip curl \
    && rm -rf /var/lib/apt/lists/*

# Detect real JAVA_HOME and store it so the entrypoint can source it
RUN echo "JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))" > /etc/java_home.env

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Android command-line tools (build 11076708 = cmdline-tools 13.0)
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
