# FuncDiffEval

This project aims to evaluate different existing function diffing techniques. It was created as a a semester prokect in [Eurecom engineering school](https://www.eurecom.fr/en) and was supported by [Talos](https://talosintelligence.com/) team.

You can find a slides about project [here](https://docs.google.com/presentation/d/1aI-6vw450eXXJht2bDZ91WQZxub33vv4mMdgqYt__eI/edit?usp=sharing)

Contributions are thankfully appreciated :)

## The DB:

The database was built from source codes that were compiled for different archs and platforms with different compilers, compiler versions and compiler flags. The compiled source codes are:
* Mirai: A botnet malware that was first seen in the summer of 2016
* unrar: A program used for compressing and decompressing files
* libclamav: An antivirus authored by Talos team

Also a modified version of the mirai source code was compiled after making four modification to 15 function of the source code. The 15 function was chosen where 5 are of small size, 5 are of medium size and 5 are of large size.
The four types of modifications are:
* 0 : change a const 
* 1 : add a check
* 2 : remove one line
* 3 : negate if condition

Function names are extracted using objdump tool (for ELF binaries) and pdbdump (for PE binaries). They are used to match functions across different versions of the compiled binaries.
 
generate_indices.py is a python code that create symbol files for each binary in the ELF and PE directories. The symbol files contain the address and name of each funtion in the binaries. Then it create DB files from each pair of functions found in the symbol files.

The symbol files and database files are found in the db directory. More information about the db are found in the [slides](https://docs.google.com/presentation/d/1aI-6vw450eXXJht2bDZ91WQZxub33vv4mMdgqYt__eI/edit?usp=sharing)

## Function Diffing Techniques:

Until this point we evaluated 4 available tools: 
1. [Fcatalog](https://www.xorpd.net/pages/fcatalog.html)
2. [Machoke](https://blog.conixsecurity.fr/machoke-hashing/)
3. [idenLib](https://github.com/secrary/idenLib)
4. [nmt4binaries](https://nmt4binaries.github.io/)

## Results

Results are stored in the results directory in csv format. The interpretation of the results is explained in the  [slides](https://docs.google.com/presentation/d/1aI-6vw450eXXJht2bDZ91WQZxub33vv4mMdgqYt__eI/edit?usp=sharing)

