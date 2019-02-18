#!/bin/bash
mkdir exc
mkdir sig
mkdir pat
mv *.pat pat/ 2>/dev/null
cd pat
for file in *.pat
do
	file_name=`basename -s .pat $file`
    sigmake "$file_name.pat" "$file_name.sig"
    if [ -f "$file_name.exc" ]; then
	    sed -i '/^;/ d' "$file_name.exc"
    fi
    sigmake "$file_name.pat" "$file_name.sig"
done
mv *.sig ../sig/
mv *.exc ../exc/
