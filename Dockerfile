###
# BUILD BASE

FROM debian:13 AS runtime-base

FROM golang:1.27-trixie AS build-base
WORKDIR /usr/src/osslsignserver

###
# EXT DEP - gemalto USB driver

FROM alpine AS driver-safenet
WORKDIR /var/tmp/extract/
ADD https://www.globalsign.com/en/safenet-drivers/USB/10.9/GlobalSign-SAC-Linux-Ubuntu-24.04.4-v10.9.zip /var/tmp
RUN apk add --no-cache unzip
RUN unzip /var/tmp/*.zip && rm /var/tmp/*.zip
WORKDIR /target/
RUN find /var/tmp/extract -name \*safenetauthenticationclient-core_\*.deb -exec mv {} /target/ \;
RUN test -f *.deb

###
# EXT DEP - proCertum

FROM alpine AS driver-certum
WORKDIR /var/tmp/extract/
ADD https://files.certum.eu/software/proCertumCardManager/Linux-Ubuntu/2.2.15/proCertumCardManager-2.2.15-x86_64-ubuntu.bin /var/tmp/
RUN sh /var/tmp/proCertumCardManager*.bin --noexec --keep --nox11 --nochown --target /var/tmp/extract/ && rm /var/tmp/proCertumCardManager*.bin
RUN apk add --no-cache coreutils

#./zz_install

ARG INSTALL_DIR="/target/opt/proCertumCardManager"

ARG SYSTEM_LIBRARY_INSTALL_DEFAULT_DIR="/target/usr/lib64"
ARG SYSTEM_LIBRARY_INSTALL_DEFAULT_SECOND_DIR="/target/usr/lib"
ARG SYSTEM_LIBRARY_INSTALL_DIR=$SYSTEM_LIBRARY_INSTALL_DEFAULT_DIR
ARG SYSTEM_LIBRARY_INSTALL_LINK_DIR=$SYSTEM_LIBRARY_INSTALL_DEFAULT_SECOND_DIR

ARG PKCS11_COMMON_PROFILE_LIBRARY_DIR=crypto3PKCS
ARG PKCS11_COMMON_PROFILE_LIBRARY='sc30pkcs11-*-MS.so'
ARG PKCS11_COMMON_PROFILE_LIBRARY_LINK=libcrypto3PKCS.so
ARG PKCS11_SECURE_PROFILE_LIBRARY_DIR=cryptoCertum3PKCS
ARG PKCS11_SECURE_PROFILE_LIBRARY='cryptoCertum3PKCS-*-MS.so'
ARG PKCS11_SECURE_PROFILE_LIBRARY_LINK=libcryptoCertum3PKCS.so

ARG SYSTEM_LIBRARY_INSTALL_DIR=$SYSTEM_LIBRARY_INSTALL_DEFAULT_SECOND_DIR

RUN mkdir -p "$SYSTEM_LIBRARY_INSTALL_DIR"

RUN mkdir -p "$INSTALL_DIR"
RUN cp -R -a * "$INSTALL_DIR"
RUN chown -R root:root "$INSTALL_DIR"
RUN chmod 755 "$INSTALL_DIR"

RUN mkdir $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR
RUN chown root:root $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR
RUN chmod 755 $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR

RUN cp -a $PKCS11_COMMON_PROFILE_LIBRARY $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR
RUN chown root:root $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR/$PKCS11_COMMON_PROFILE_LIBRARY
RUN rm -f $SYSTEM_LIBRARY_INSTALL_LINK_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_LINK
RUN ln -rs $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_DIR/$PKCS11_COMMON_PROFILE_LIBRARY $SYSTEM_LIBRARY_INSTALL_LINK_DIR/$PKCS11_COMMON_PROFILE_LIBRARY_LINK

RUN mkdir $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR
RUN chown root:root $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR
RUN chmod 755 $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR

RUN cp -a $PKCS11_SECURE_PROFILE_LIBRARY $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR
RUN chown root:root $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR/$PKCS11_SECURE_PROFILE_LIBRARY
RUN rm -f $SYSTEM_LIBRARY_INSTALL_LINK_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_LINK
RUN ln -rs $SYSTEM_LIBRARY_INSTALL_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_DIR/$PKCS11_SECURE_PROFILE_LIBRARY $SYSTEM_LIBRARY_INSTALL_LINK_DIR/$PKCS11_SECURE_PROFILE_LIBRARY_LINK

# remove installer scripts
RUN rm "$INSTALL_DIR"/zz_* "$INSTALL_DIR"/proCertumCardManager_uninstall_pl

# install license
RUN install -Dm644 -t "$pkgdir/usr/share/licenses/$pkgname" "$INSTALL_DIR"/proCertumCardManager_*_licence.rtf

###
# GO BUILD

FROM build-base AS build

ENV GOCACHE=/go/cache

# download deps
COPY go.* .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/go/cache \
	go mod download

# compile the app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/go/cache \
	go build -v -ldflags "-s -w" ./cmd/osslsignserver

RUN ldd ./osslsignserver

###
# FINAL RUNTIME IMAGE

# TODO - fix compat with static-debian13
#FROM gcr.io/distroless/static-debian13:nonroot

FROM runtime-base AS osslsignserver

# install runtime deps
#
# pcscd is meant to be run separately in Kubernetes, it does not run by default
COPY --from=driver-safenet /target/*.deb .
ARG PACKAGES="\
	osslsigncode \
	libengine-pkcs11-openssl \
	pcscd \
"
RUN apt update && apt install -y ${PACKAGES} ./*.deb

COPY --from=driver-certum /target/ /

COPY --from=build /usr/src/osslsignserver/osslsignserver /
CMD ["/osslsignserver"]
STOPSIGNAL SIGTERM

