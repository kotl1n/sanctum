FROM rust:1.88-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mingw-w64-x86-64 python3 curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-pc-windows-gnu
RUN mkdir /opt/windows-python && curl --fail --location --retry 3 \
    https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip \
    --output /tmp/python.zip && unzip -q /tmp/python.zip -d /opt/windows-python \
    && rm /tmp/python.zip
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine \
    WINEDEBUG=-all WINEPREFIX=/tmp/sanctum-wine WINEARCH=win64
WORKDIR /workspace
RUN mkdir /opt/windows-git && curl --fail --location --retry 3 https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/MinGit-2.47.1-64-bit.zip --output /tmp/git.zip && unzip -q /tmp/git.zip -d /opt/windows-git && rm /tmp/git.zip
ENV WINEPATH="Z:\\opt\\windows-git\\cmd"
RUN dpkg --add-architecture i386 \
    && mkdir -p /etc/apt/keyrings \
    && curl --fail --location https://dl.winehq.org/wine-builds/winehq.key --output /etc/apt/keyrings/winehq.asc \
    && printf '%s\n' 'Types: deb' 'URIs: https://dl.winehq.org/wine-builds/debian/' \
        'Suites: bookworm' 'Components: main' 'Architectures: amd64 i386' \
        'Signed-By: /etc/apt/keyrings/winehq.asc' > /etc/apt/sources.list.d/winehq.sources \
    && apt-get update && apt-get install -y --no-install-recommends wine-stable \
    && rm -rf /var/lib/apt/lists/* \
    && /opt/wine-stable/bin/wine --version
RUN rustup component add clippy
ENV PATH="/opt/wine-stable/bin:${PATH}"
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
