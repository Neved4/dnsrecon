FROM	golang:1.25.5-alpine	AS	build
WORKDIR	/src
COPY	go.mod	go.sum	./
RUN	go	mod	download
COPY	.	.
ARG	TARGETOS=linux
ARG	TARGETARCH=amd64
RUN	CGO_ENABLED=0	GOOS=$TARGETOS	GOARCH=$TARGETARCH	\
	go	build	-o	/out/dnspeek	./cmd/dnspeek

FROM	alpine:3.20
RUN	apk	add	--no-cache	ca-certificates
RUN	adduser	-D	-u	10001	dnspeek
WORKDIR	/app
COPY	--from=build	/out/dnspeek	/usr/local/bin/dnspeek
COPY	--from=build	/src/test	./test
ENV	DNSPEEK_DATA=/app/test
USER	dnspeek
ENTRYPOINT	["dnspeek"]
