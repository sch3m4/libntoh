#!/usr/bin/env bash

# this scripts follows the steps that you
# should follow to compile and link against libntoh:
#
# $ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# $ pkg-config --libs --cflags libntoh
# -I/usr/local/include/libntoh  -L/usr/local/lib -lntoh

pkgconfig=$(which pkg-config)
cmake=$(which cmake)
make=$(which make)
pkgconfig_path=''
libntoh_pcpath='/usr/local/lib/pkgconfig'
build_dir='build'

if [ -z "$pkgconfig" ]
then
	echo "[w] pkg-config not found! Good luck compiling..."
	exit 1
else
	echo "[i] pkg-config found: $pkgconfig"
fi

if [ -z "$cmake" ]
then
	echo "[e] Cannot compile without cmake binary"
	exit 2
else
	echo "[i] cmake found: $cmake"
fi

if [ -z "$make" ]
then
	echo "[e] Cannot compile without make binary"
	exit 3
else
	echo "[i] make found: $make"
fi

pkgconfig_path=$(echo $PKG_CONFIG_PATH)
if [ -z "$pkgconfig_path" ]
then
	pkgconfig_path="$libntoh_pcpath"
else
	pkgconfig_path="$pkgconfig_path:$libntoh_pcpath"
fi

echo "[i] PKG_CONFIG_PATH set to: $pkgconfig_path"
echo ''

rm -rf $build_dir 2>/dev/null
mkdir $build_dir 2>/dev/null
cd $build_dir
$cmake ../
$make

if [ $? -eq 0 ]
then
	response=''
	while [ $(echo -n "$response" | grep -c "[yn]") -eq 0 ]
	do
		read -e -p "Do you want to perform the installation? [y/n]: " -i "y" response
	done

	if [ "$response" == "y" ]
	then
		command='make'
		if [ $UID -gt 0 ]
		then
			command="sudo $command"
		fi
		command="$command install"
		$command
	fi
fi

unset pkgconfig_path build_dir cmake make pkgconfig libntoh_pcpath
exit 0
