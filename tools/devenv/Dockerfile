FROM linuxcontainers/debian-slim:12
LABEL org.zpr.version="0.0.3"
LABEL org.opencontainers.image.source=https://github.com/org-zpr/zpr-core
LABEL org.opencontainers.image.description="zpr build env DEB"
LABEL org.opencontainers.image.version="0.0.3"

WORKDIR /opt

RUN apt-get -y update \
&& apt-get install -y wget curl build-essential git \
&& apt autoremove


# deps for thrift
RUN apt-get install -y \
libboost-dev libboost-test-dev libboost-program-options-dev libboost-filesystem-dev libboost-thread-dev \
libevent-dev automake libtool flex bison pkg-config g++ libssl-dev \
&& apt autoremove


# go:
RUN wget -nv https://go.dev/dl/go1.23.1.linux-amd64.tar.gz \
&& tar xf go1.23.1.linux-amd64.tar.gz \
&& mkdir -p /opt/gopath

ENV GOPATH=/opt/gopath
ENV GOROOT=/opt/go


# rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >rustup.sh \
&& /bin/sh ./rustup.sh --default-toolchain stable -y



# thrift
RUN wget -nv https://dlcdn.apache.org/thrift/0.21.0/thrift-0.21.0.tar.gz \
&& tar xf thrift-0.21.0.tar.gz \
&& cd thrift-0.21.0 \
&& ./bootstrap.sh \
&& ./configure --with-go --with-rs --without-python --without-py3 --without-swift --without-php --without-kotlin --without-java --without-nodejs --without-netstd --disable-tests --disable-tutorial --disable-dependency-tracking \
&& make && make install \
&& cd /opt \
&& rm -rf thrift-0.21.0 && rm thrift-0.21.0.tar.gz




ENV PATH="$PATH:/opt/go/bin:/root/.cargo/bin"



