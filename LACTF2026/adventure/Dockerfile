FROM ubuntu:noble
RUN apt-get update && apt-get install -y socat
COPY chall /app/run
COPY flag.txt /app/flag.txt
WORKDIR /app
RUN chmod +x run
# Expose qua socat
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:./run