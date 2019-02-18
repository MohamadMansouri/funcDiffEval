# Fcatalog
FCatalog is the Functions Catalog. It is a tool for quickly finding similar functions from a large database of functions.
You can find more explanation here https://www.xorpd.net/pages/fcatalog.html

## What does this folder contatin?
* The source file of the libcatalog library
* Implementations of the evaluation of the fcatalog technique on the database:
1. eval_fcatalog applies fcatalog on the positive matches:
	* It uses radare2 to extract the assembly from the db files
	* The results are stored in results/fcatalog_pstv
2. eval_fcatalog_ngtv applies fcatalog on the negative matches:
	* It uses radare2 to extract the assembly from the db files
	* The results are stored in results/fcatalog_ngtv
3. eval_fcatalog_objdump applies fcatalog on the positive matches:
	* It uses objdump to extract the assembly from the db files
	* The results are stored in results/fcatalog_pstv

## Notes:
 * Use eval_fcatalog_objdump only if you dont have radare2.
 * These codes apply fcatalog only on a sample of 10k entries of the database.
 * Please be sure to execute the files from their directory