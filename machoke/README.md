# machoke

CFG-based fuzzy hash for malware classification
by [CERT-Conix](http://blog.conixsecurity.fr/machoke-hashing/).
machoke was authored by ancelot Bogard.

## What does this folder contatin?

 * machoke.py represents the original source code of machoke
 * Implementation of the evaluation of machoke on on the database:
1. machoke_pstv.py applies machoke on the positive matches of functions 
	* The results are stored in results/machoke_pstv
2. machoke_ngtv.py applies machoke on the negative matches of functions
	* The results are stored in results/machoke_ngtv
3. machoke_on_bins.py works instead on binaries.
	* It takes as an input the the output file of the original machoke code. (to evaluate the database run machoke on all files in the db)
	* The results are stored in results/machoke_prog

## Notes:
 * 1 and 2 apply machoke only on a sample of 10k entries of the database.
 * Please be sure to execute the files from their directory