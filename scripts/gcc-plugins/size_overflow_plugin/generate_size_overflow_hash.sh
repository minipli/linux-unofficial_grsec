#!/bin/bash

# This script generates the hash table (size_overflow_hash.h) for the size_overflow gcc plugin (size_overflow_plugin.c).

header1="size_overflow_hash.h"
database="size_overflow_hash.data"
n=65536
hashtable_name="size_overflow_hash"

usage() {
cat <<EOF
usage: $0 options
OPTIONS:
        -h|--help               help
	-o			header file
	-d			database file
	-n			hash array size
	-s			name of the hash table
EOF
    return 0
}

while true
do
    case "$1" in
    -h|--help)	usage && exit 0;;
    -n)		n=$2; shift 2;;
    -o)		header1="$2"; shift 2;;
    -d)		database="$2"; shift 2;;
    -s)		hashtable_name="$2"; shift 2;;
    --)		shift 1; break ;;
     *)		break ;;
    esac
done

create_defines() {
	for i in `seq 0 31`
	do
		echo -e "#define PARAM"$i" (1U << "$i")" >> "$header1"
	done
	echo >> "$header1"
}

create_structs() {
	rm -f "$header1"

	create_defines

	cat "$database" | while read data
	do
		data_array=($data)
		struct_hash_name="${data_array[0]}"
		funcn="${data_array[1]}"
		context="${data_array[2]}"
		params="${data_array[3]}"
		next="${data_array[5]}"

		echo "const struct size_overflow_hash $struct_hash_name = {" >> "$header1"

		echo -e "\t.next\t= $next,\n\t.name\t= \"$funcn\",\n\t.context\t= \"$context\"," >> "$header1"
		echo -en "\t.param\t= " >> "$header1"
		line=
		for param_num in ${params//-/ };
		do
			line="${line}PARAM"$param_num"|"
		done

		echo -e "${line%?},\n};\n" >> "$header1"
	done
}

create_headers() {
	echo "const struct size_overflow_hash * const $hashtable_name[$n] = {" >> "$header1"
}

create_array_elements() {
	index=0
	grep -v "nohasharray" $database | sort -n -k 5 | while read data
	do
		data_array=($data)
		i="${data_array[4]}"
		hash="${data_array[0]}"
		while [[ $index -lt $i ]]
		do
			echo -e "\t["$index"]\t= NULL," >> "$header1"
			index=$(($index + 1))
		done
		index=$(($index + 1))
		echo -e "\t["$i"]\t= &"$hash"," >> "$header1"
	done
	echo '};' >> $header1
}

size_overflow_plugin_dir=`dirname $header1`
if [ "$size_overflow_plugin_dir" != '.' ]; then
	mkdir -p "$size_overflow_plugin_dir" 2> /dev/null
fi

create_structs
create_headers
create_array_elements

exit 0
