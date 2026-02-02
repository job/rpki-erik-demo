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
    libtls26 \
    libtls-dev \
    libdigest-sha-perl \
    libexpat1-dev \
    sudo
cpanm Set::IntSpan Net::CIDR::Set
wget https://ftp.openssl.org/source/openssl-1.0.2p.tar.gz \
    && tar xf openssl-1.0.2p.tar.gz \
    && cd openssl-1.0.2p \
    && ./config enable-rfc3779 \
    && make \
    && make install
