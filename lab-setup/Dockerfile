FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc make pkg-config python3 curl \
    libgsf-1-dev libextractor-dev libextractor3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy exploit files
COPY poc/ poc/
COPY exploit/ exploit/

# Build the vulnerable extract_server from source (NO hardening flags)
# This is what ./configure && make produces upstream
RUN gcc -O2 -fno-stack-clash-protection -fno-stack-protector \
    -o /usr/local/bin/extract_server exploit/extract_server.c \
    -lextractor

# Build source OLE2 plugin without hardening
COPY lab-setup/ole2_extractor.c lab-setup/convert.c lab-setup/convert.h \
     lab-setup/extractor.h lab-setup/platform.h lab-setup/gettext.h \
     lab-setup/config.h /tmp/src/
RUN gcc -O2 -fno-stack-clash-protection -fno-stack-protector -fPIC -shared \
    -o /usr/lib/x86_64-linux-gnu/libextractor/libextractor_ole2.so \
    /tmp/src/ole2_extractor.c /tmp/src/convert.c \
    -I/tmp/src $(pkg-config --cflags --libs libgsf-1) -DHAVE_CONFIG_H

# Upload server
COPY lab-setup/upload_server.py /app/

EXPOSE 8080

# Run with limited stack (typical for containers)
CMD ["bash", "-c", "echo 'Vulnerable server on :8080'; python3 /app/upload_server.py"]
