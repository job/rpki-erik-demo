#!/bin/sh
apt-get update -y
apt-get install -y \
    libhttp-daemon-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    libconvert-asn1-perl \
    libclass-accessor-perl \
    libssl-dev \
    libyaml-perl \
    libxml-libxml-perl \
    libio-capture-perl \
    libnet-ip-perl \
    make \
    wget \
    patch \
    gcc \
    rsync \
    libfile-slurp-perl \
    libjson-xs-perl \
    cpanminus \
    jq \
    vim \
    git \
    libdatetime-perl \
    libtls-dev \
    libdigest-sha-perl \
    libexpat1-dev \
    libdevel-nytprof-perl \
    libdevel-cover-perl \
    libnet-ip-xs-perl \
    libtest-most-perl \
    libfile-slurp-perl \
    libio-socket-ip-perl \
    libio-socket-ssl-perl \
    libtest-tcp-perl \
    libnet-async-http-perl \
    libtest-fatal-perl \
    libnet-https-nb-perl \
    libcgi-pm-perl \
    libhttp-server-simple-perl \
    libtest-http-server-simple-perl \
    openssl \
    libio-async-perl \
    libfuture-asyncawait-perl \
    libnet-async-http-perl \
    libclass-unload-perl \
    parallel \
    sudo
apt-get remove -y \
    libfuture-xs-perl
cpanm Set::IntSpan Net::CIDR::Set
git clone https://github.com/job/rpkitouch
cd rpkitouch
make && mkdir -p /usr/local/man/man8 && make install
