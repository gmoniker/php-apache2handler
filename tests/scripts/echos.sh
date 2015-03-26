#!/bin/bash
for var in "${@}"; do
	printf -- "GET /%s HTTP/1.1\nHost: localhost\n\n" "$var"
done | nc localhost 80
