FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends strongswan-swanctl strongswan-charon libstrongswan-standard-plugins libstrongswan-extra-plugins iproute2 iputils-ping tcpdump curl python3 procps && rm -rf /var/lib/apt/lists/*
COPY testbed/scripts/entrypoint.sh /usr/local/bin/lab-entrypoint
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
