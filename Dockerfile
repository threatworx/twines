FROM threatworx/twigs:latest
  
LABEL MAINTAINER="Ketan Nilangekar"
LABEL EMAIL="ketan@threatwatch.io"

USER root
ENV PATH="/opt/zeek/bin:$PATH"
ENV LISTEN_ON="zeek0"

#SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
COPY src/. /usr/share/twines
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/share/twines/run.sh"]
