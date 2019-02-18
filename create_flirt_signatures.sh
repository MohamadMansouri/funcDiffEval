path_ELF=./ELF
path_PE=./PE
ida_path=/opt/ida-7.0
# set -x
create_pattern_ELF() {
    for i in "$1"/*;do
        if [ -d "$i" ];then
            create_pattern_ELF "$i"
        elif [ -f "$i" ]; then
            execute_ida_ELF $i
        fi
    done
}


create_pattern_PE() {
    for i in "$1"/*;do
        if [ -d "$i" ];then
            create_pattern_PE "$i"
        elif [ -f "$i" ]; then
            echo "$i" | awk -F. '{print $NF}' | grep -q "dll" 
            dll=$?
	        echo "$i" | awk -F. '{print $NF}' | grep -q "exe" 
            if [ $? -eq 0 ] || [ "$dll" -eq 0 ]
            then 
	            execute_ida_PE $i
	        fi
        fi
    done
}


execute_ida_ELF() {
	file "$1" | grep -q "32-bit" 
	if [ $? -eq 0 ]
	then
		$ida_path/idat  -A -S\"$ida_path/python/idb2pat.py\" "$1"
	else
		file "$1" | grep -q "64-bit" 
		if [ $? -eq 0 ]
		then
			$ida_path/idat64  -A -S\"$ida_path/python/idb2pat.py\" "$1"
		fi
	fi
	dir=$(dirname "$1")
	echo "finished $1"
	rm -f $dir/*.nam
	rm -f $dir/*.id
	rm -f $dir/*.til
	rm -f $dir/*.i64 2>/dev/null
	rm -f $dir/*.idb 2>/dev/null
	mv $dir/*.pat ./flirt_sig/
}

execute_ida_PE() {
	file "$1" | grep -q "PE32+" 
	if [ $? -eq 1 ]
	then
		$ida_path/idat  -A -S\"$ida_path/python/idb2pat.py\" "$1"
	else
		$ida_path/idat64  -A -S\"$ida_path/python/idb2pat.py\" "$1"
	fi
	dir=$(dirname "$1")
	echo "finished $1"
	rm -f $dir/*.nam
	rm -f $dir/*.id
	rm -f $dir/*.til
	rm -f $dir/*i
	rm -f $dir/*.i64 2>/dev/null
	rm -f $dir/*.idb 2>/dev/null
	mv $dir/*.pat ./flirt_sig/
}
create_pattern_ELF $path_ELF
create_pattern_PE $path_PE