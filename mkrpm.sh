#!/bin/sh
set -e

./autogen.sh
./configure --prefix=/usr
make rpm
