FROM ubuntu:24.04
RUN apt-get update && apt-get install -y postfix && rm -rf /var/lib/apt/lists/*
EXPOSE 2525
CMD ["smtp-sink", "-c", "-u", "nobody", "0.0.0.0:2525", "1000"]
