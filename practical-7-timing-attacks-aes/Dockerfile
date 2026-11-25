# Hosted version of the AES timing attack exercise.
#
# Build:  docker build -t timing-attacks-aes .
# Run:    docker run -d -p 8000:8000 timing-attacks-aes --key <32 hex> --flag 'flag{...}'
#
# Arguments after the image name are passed to server.py, so --key, --flag
# and --noise can be set at run time.

FROM python:3.12-slim

WORKDIR /app
COPY server.py .

USER nobody
EXPOSE 8000

ENTRYPOINT ["python3", "server.py", "--host", "0.0.0.0", "--port", "8000"]
