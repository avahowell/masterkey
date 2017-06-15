#!/bin/bash
set -e

name="$1"
if [[ -z $name ]]; then
	echo "Usage: $0 name version"
	exit 1
fi

version="$2"
if [[ -z $version ]]; then
	echo "Usage: $0 name version"
	exit 1
fi

for os in darwin linux windows; do
	folder=release/$name-$version-$os-amd64
	rm -rf $folder
	mkdir -p $folder
	bin="$name"
	if [ "$os" == "windows" ]; then
		bin="${name}.exe"
	fi
	echo "building ${os}..."

	GOOS=${os} GOARCH=amd64 go build -o $folder/$bin .
	cp LICENSE README.md $folder

	(
		cd release
		zip -rq $name-$version-$os-amd64.zip $name-$version-$os-amd64
	)
done

echo "done"

