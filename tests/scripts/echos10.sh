#!/bin/bash
for var in "${@}"; do
	printf -- "GET /%s HTTP/1.0\nHost: localhost\n\n" "$var"
done | nc localhost 80
