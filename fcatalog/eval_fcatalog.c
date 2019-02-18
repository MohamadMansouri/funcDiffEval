#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <r_socket.h>
#include <time.h>
#include "catalog1.h"

#define FILES_PATH "../.."
#define DB_PATH "../../db/databases_sorted"
#define OUT_PATH "../../results/fcatalog_pstv"
#define ARCH_DB "different_archs.txt"
#define COMP_DB "different_compilers.txt"
#define VERS_DB "different_compiler_versions.txt"
#define FLAG_DB "different_flags.txt"
#define FUNC_DB "different_functions.txt"
#define PLAT_DB "different_platforms.txt"
#define RAND_DB "random.txt"
#define MOD0_L_DB "large_size_modified0.txt"
#define MOD1_L_DB "large_size_modified1.txt"
#define MOD2_L_DB "large_size_modified2.txt"
#define MOD3_L_DB "large_size_modified3.txt"
#define MOD0_M_DB "medium_size_modified0.txt"
#define MOD1_M_DB "medium_size_modified1.txt"
#define MOD2_M_DB "medium_size_modified2.txt"
#define MOD3_M_DB "medium_size_modified3.txt"
#define MOD0_S_DB "small_size_modified0.txt"
#define MOD1_S_DB "small_size_modified1.txt"
#define MOD2_S_DB "small_size_modified2.txt"
#define MOD3_S_DB "small_size_modified3.txt"
#define NB_OF_DBS 19
#define NUM_PERMS 64
#define STREAM_READ 10
#define SAMPLE 10000

struct Sim_result
{
	float sim;
	uint size1;
	uint size2;
	char* bin1;
	char* bin2;
	char* var1;
	char* var2;
};

char* DBs[] = {"ARCH_DB", "COMP_DB", "VERS_DB", "FLAG_DB", "FUNC_DB", "PLAT_DB", "RAND_DB", "MOD0_S_DB", "MOD1_S_DB", "MOD2_S_DB", "MOD3_S_DB",
			"MOD0_M_DB", "MOD1_M_DB", "MOD2_M_DB", "MOD3_M_DB", "MOD0_L_DB", "MOD1_L_DB", "MOD2_L_DB", "MOD3_L_DB"};




void print_usage(){
	printf("Usage: ./eval_fcatalog [database]\n[database] = "
			"%2s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n%20s\n",
			"ARCH_DB", "COMP_DB", "VERS_DB", "FLAG_DB", "FUNC_DB", "PLAT_DB", "RAND_DB", "MOD0_S_DB", "MOD1_S_DB", "MOD2_S_DB", "MOD3_S_DB",
			"MOD0_M_DB", "MOD1_M_DB", "MOD2_M_DB", "MOD3_M_DB", "MOD0_L_DB", "MOD1_L_DB", "MOD2_L_DB", "MOD3_L_DB" );
}

char* db_file(char* db_name){
	char* db_file_name;

	if (!strcmp(db_name,"ARCH_DB"))
		db_file_name = strdup(ARCH_DB);
	else if (!strcmp(db_name,"COMP_DB"))
		db_file_name = strdup(COMP_DB);
	else if (!strcmp(db_name,"VERS_DB"))
		db_file_name = strdup(VERS_DB);
	else if (!strcmp(db_name,"FLAG_DB"))
		db_file_name = strdup(FLAG_DB);
	else if (!strcmp(db_name,"FUNC_DB"))
		db_file_name = strdup(FUNC_DB);
	else if (!strcmp(db_name,"PLAT_DB"))
		db_file_name = strdup(PLAT_DB);
	else if (!strcmp(db_name,"RAND_DB"))
		db_file_name = strdup(RAND_DB);
	else if (!strcmp(db_name,"MOD3_L_DB"))
		db_file_name = strdup(MOD3_L_DB);
	else if (!strcmp(db_name,"MOD2_L_DB"))
		db_file_name = strdup(MOD2_L_DB);
	else if (!strcmp(db_name,"MOD1_L_DB"))
		db_file_name = strdup(MOD1_L_DB);
	else if (!strcmp(db_name,"MOD0_L_DB"))
		db_file_name = strdup(MOD0_L_DB);
	else if (!strcmp(db_name,"MOD3_M_DB"))
		db_file_name = strdup(MOD3_M_DB);
	else if (!strcmp(db_name,"MOD2_M_DB"))
		db_file_name = strdup(MOD2_M_DB);
	else if (!strcmp(db_name,"MOD1_M_DB"))
		db_file_name = strdup(MOD1_M_DB);
	else if (!strcmp(db_name,"MOD0_M_DB"))
		db_file_name = strdup(MOD0_M_DB);
	else if (!strcmp(db_name,"MOD3_S_DB"))
		db_file_name = strdup(MOD3_S_DB);
	else if (!strcmp(db_name,"MOD2_S_DB"))
		db_file_name = strdup(MOD2_S_DB);
	else if (!strcmp(db_name,"MOD1_S_DB"))
		db_file_name = strdup(MOD1_S_DB);
	else if (!strcmp(db_name,"MOD0_S_DB"))
		db_file_name = strdup(MOD0_S_DB);

	return db_file_name;
}

unsigned int count_similars(unsigned int* arr1, unsigned int* arr2,
        unsigned int len) {

    unsigned int count = 0;
    for(unsigned int i=0; i<len; ++i) {
        if(arr1[i] == arr2[i]) {
            count += 1;
        }
    }
    return count;
}

char* get_bin(char* path){
	if (path){
		int j = 0;
		int i = 0;
		for (i = strlen(path)-1; i >= 0; --i){
			if(path[i] == '-')
				j = i;
			if(path[i] == '/')
				break;
		}
		i++;
		if(i != 1 && j>i){
			char* bin_name = malloc(j - i + 1);
			if(bin_name){
				strncpy(bin_name, path + i, j-i);
				bin_name[j-i] = 0;
				return bin_name;
			}
			else 
				return NULL;
		}
	}
	return NULL;
}

char* get_var(char* path){
	if(!path)
		return NULL;
	uint j = 0; 
	uint length = strlen(path);

	for (int i = length - 1 ; i >= 0; --i)
		if(path[i] == '-' && ++j == 4){
				i++;
				char* var = malloc(length - i + 1);
				if(var){
					strncpy(var, path + i, length - i);
					var[length - i] = 0;
					return var;
				}
				else
					return NULL;
		}
	return NULL;
}

uint count_lines(FILE* fp){
	int ch = 0;
 	uint lines = 0;
  while ((ch = fgetc(fp)) != EOF){
    if (ch == '\n')
  lines++;
  }
  rewind(fp);
  return lines;
}

float run_fcatalog(char* asm1, char* asm2){


	unsigned int s1[NUM_PERMS];
	unsigned int s2[NUM_PERMS];

	sign(asm1, strlen(asm1), s1, NUM_PERMS);
	sign(asm2, strlen(asm2), s2, NUM_PERMS);

	unsigned int sim_count =  count_similars(s1, s2, NUM_PERMS);


	return (float) (sim_count*100)/NUM_PERMS;

}


void evaluate(char* db_path, char* DB){
	struct timeval start, end, start_raw, end_raw;
	double time, time_raw;
	double time_total, time_total_raw;

	FILE* fp_read = fopen(db_path, "r");
	if (!fp_read){
		printf("Error opening the DB...\nExiting\n");
		exit(-1);
	}

	uint nb_lines = count_lines(fp_read);
	char* db_file_name = db_file(DB);
	char output[strlen(OUT_PATH) + strlen(db_file_name) + 2];
	sprintf(output, "%s/%s\0", OUT_PATH, db_file_name );
	free(db_file_name);

	FILE* fp_write= fopen(output, "w");
	if(!fp_write){
		printf("Error opening output file...\nExiting\n");
		exit(-1);
	}


  char line[256];
  ssize_t read;
  size_t count = 0;
  
  regex_t regex;
  regmatch_t match[5];

  if (regcomp(&regex, "^(.*):(.*) (.*):(.*)\n$", REG_EXTENDED)){
  	printf("Error parsing the DB...\n");
  	exit(-1);
  }

	char old_path1[100];
	char old_path2[100];
	R2Pipe* r21;
	R2Pipe* r22;

	int skip = STREAM_READ * (nb_lines) / SAMPLE;
	int skip_count = --skip;
	uint read_count = 0;
	printf("writing in stream %d\n", STREAM_READ );
	printf("skipping %d\n", skip );
  while(fgets ( line, sizeof line, fp_read ) != NULL ){

  	if(skip_count < skip){
  		skip_count++;
  		count++;
  		continue;
  	}
  	gettimeofday(&start_raw, NULL);
  	count++;
  	read_count++;
  	if(read_count == STREAM_READ){
  		skip_count = 0;
  		read_count = 0;
  	}
  	if (regexec(&regex, line, 5, match, 0))
  		continue;
  	uint size = match[1].rm_eo - match[1].rm_so;
  	char path1[size+1];
  	strncpy(path1,line + match[1].rm_so, size);
  	path1[size] = 0;
  	size = match[2].rm_eo - match[2].rm_so;
  	char addr1[size+1];
  	strncpy(addr1,line + match[2].rm_so, size);
  	addr1[size] = 0;

  	size = match[3].rm_eo - match[3].rm_so;
  	char path2[size+1];
  	strncpy(path2,line + match[3].rm_so, size);
  	path2[size] = 0;

  	size = match[4].rm_eo - match[4].rm_so;
  	char addr2[size+1];
  	strncpy(addr2,line + match[4].rm_so, size);
  	addr2[size] = 0;


		char full_path1[strlen(FILES_PATH) + strlen(path1) + 2];
		char full_path2[strlen(FILES_PATH) + strlen(path2) + 2];

		sprintf(full_path1, "%s/%s\0", FILES_PATH, path1);
		sprintf(full_path2, "%s/%s\0", FILES_PATH, path2);
		if (strcmp(old_path1, full_path1)){
			r2p_close(r21);
			char r2open1[strlen("radare2 -q0 ") + strlen(full_path1) + 1];	
			strcpy(r2open1, "radare2 -q0 ");
			strcat(r2open1, full_path1);
			r21 = r2p_open (r2open1);
			if (!r21)
				continue;
			strcpy(old_path1, full_path1);
			old_path1[strlen(full_path1)] = 0;
		} 
		if(strcmp(old_path2,full_path2)){
			r2p_close(r22);
			char r2open2[strlen("radare2 -q0 ") + strlen(full_path2) + 1];
			strcpy(r2open2, "radare2 -q0 ");
			strcat(r2open2, full_path2);
			r22 = r2p_open(r2open2);
			if(!r22)
				continue;
			strcpy(old_path2, full_path2);
			old_path2[strlen(full_path2)] = 0;
		}
			

		char af[24];
		char p8[54];
		snprintf(af, 24, "af @ 0x%s", addr1);
		snprintf(p8, 54, "%s; p8 $FS @ 0x%s",af, addr1);

		char* asm1 = r2p_cmd(r21, p8);

		if (!asm1)
			continue;

		snprintf(af, 24, "af @ 0x%s", addr2);
		snprintf(p8, 54, "%s; p8 $FS @ 0x%s",af, addr2);

		
		char* asm2 = r2p_cmd(r22, p8);
		if (!asm2)
			continue;

		gettimeofday(&start, NULL);
  	float similarity = run_fcatalog(asm1, asm2);
		gettimeofday(&end, NULL);
		time = ((double)((end.tv_sec*1e6 + end.tv_usec) - (start.tv_sec*1e6 + start.tv_usec))) / 1e6;

  	fprintf(fp_write, "%d, %d, %d, %.2f", count , strlen(asm1), strlen(asm2), similarity);

  	char* bin1 = get_bin(path1);
  	char* var1 = get_var(path1);
  	char* bin2 = get_bin(path2);
  	char* var2 = get_var(path2);
		if(bin1){
			fprintf(fp_write, ", %s", bin1);
			free(bin1);
		}
		if(var1){
			fprintf(fp_write, ", %s", var1);
			free(var1);
		}
		if(bin2){
			fprintf(fp_write, ", %s", bin2);
			free(bin2);
		}
		if(var2){
			fprintf(fp_write, ", %s", var2);
			free(var2);
		}

		time_total += time;
		time_total_raw += time_raw;

		free(asm1);
		free(asm2);

		gettimeofday(&end_raw, NULL);
		time_raw = ((double)((end_raw.tv_sec*1e6 + end_raw.tv_usec) - (start_raw.tv_sec*1e6 + start_raw.tv_usec)) )/ 1e6;
		
		fprintf(fp_write, ", %.5f, %.5f\n", time, time_raw );
		if (!(count % 10))
			printf("%d out of %d (%.2f %)\t Time elapsed = %.2f sec\n",count, nb_lines, ((float)count*100)/nb_lines, time_total_raw);

  }

	r2p_close(r22);
	r2p_close(r21);
  fclose(fp_read);
  fclose(fp_write);
  regfree(&regex);

  printf("TOTAL = %f sec\n", time_total );
  printf("TOTAL_RAW = %f sec\n", time_total_raw );
  printf("Find %d entries in the database\n", count);
  return;

}

int main(int argc, char **argv){
	char DB[33]; 
	DB[0] = '\0';

	if (argc != 2){
		print_usage();
		exit(-1);
	}
	else{
		for (int i = 0; i < NB_OF_DBS; ++i)
			if (!strcmp(argv[1],DBs[i])){
				strncpy(DB,argv[1],strlen(argv[1]));
				DB[strlen(argv[1])] = '\0';
				break;
			}
		if (!strlen(DB)){
			print_usage();
			exit(-1);
		}
	}
	char* db_file_name = db_file(DB);
	printf("Evaluating Fcatalog on DB %s located in = %s/%s\n", DB, DB_PATH ,db_file_name);
	char db_path[strlen(DB_PATH) + strlen(db_file_name) + 2];
	sprintf(db_path, "%s/%s\0", DB_PATH, db_file_name);
	free(db_file_name);
	evaluate(db_path, DB);

}