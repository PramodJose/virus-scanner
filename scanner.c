//	----------------------------- HEADER FILES ----------------------------- 

#include <stdio.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>


//	----------------------------- CONSTANTS ----------------------------- 

#define T					10
#define MAX_PATH_LEN		1024
#define DEFAULT_ALLOC_SIZE	8
#define HASH_LEN			MD5_DIGEST_LENGTH
#define FILE_BUF_SIZE		4096


//	----------------------------- GLOBAL VARIABLES ----------------------------- 

const char SIGNATURE[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};
enum scan_t {store, scan};		// Used by scan_directory.
typedef enum scan_t scan_t;

char **hash_n_files = NULL;		// Each row contains a hash concatenated with the corresponding file name, terminated by a NULL.
size_t num_of_files = 0, allocated_size = 0;	// Used to keep track of the allocated size of hash_n_files.


//	----------------------------- FUNCTIONS ----------------------------- 

//	Compares the first n bytes of two byte arrays.
//	Returns 1 if same; 0 if unequal.
int byte_arr_comp(const char* restrict a_arr, const char* restrict b_arr, int n)
{
	int i;
	for (i = 0; i < n; ++i)
		if (a_arr[i] != b_arr[i])
			return 0;
	return 1;
}


//	Detects the signature in the file sent it to as argument.
//	Returns 1 if signature found, else 0.
int detect_signature(const char* restrict f_name)
{
	char chunk[sizeof(SIGNATURE)];
	FILE* in_fh = fopen(f_name, "rb");
	int position = 0;

	while (fread(chunk, sizeof(char), sizeof(SIGNATURE), in_fh) == sizeof(SIGNATURE))
	{
		if (byte_arr_comp(chunk, SIGNATURE, sizeof(SIGNATURE)))
		{
			fclose(in_fh);
			return 1;
		}
		++position;
		fseek(in_fh, position, SEEK_SET);
	}

	fclose(in_fh);
	return 0;
}


/*	Calculates the hash of a file (sent as arg); appends the file name after HASH_LEN bytes; stores it in a
**	dynamically allocated byte array and returns it to the caller. It is the responsibility of the caller
**	to free this dynamic byte array.
*/
unsigned char* calc_MD5 (const char* restrict f_name)
{
	// + 1 (during dyn. alloc. on next line) for the NULL at the end of the file name
	unsigned char read_buffer[FILE_BUF_SIZE], *hash = malloc(sizeof(char) * (HASH_LEN) + strlen(f_name)  + 1);
	size_t bytes, i, j;
	FILE* in_fh = fopen (f_name, "rb");
	MD5_CTX md_context;

	if (in_fh == NULL)
	{
		fprintf(stderr, "Error while opening %s\n", f_name);
		exit(1);
	}
	if (hash == NULL)
	{
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	MD5_Init(&md_context);
	while((bytes = fread(read_buffer, sizeof(char), sizeof(read_buffer), in_fh)) != 0)
		MD5_Update(&md_context, read_buffer, bytes);
	MD5_Final(hash, &md_context);
	fclose(in_fh);

	for(i = 0, j = HASH_LEN; hash[j] = f_name[i]; ++i, ++j);

	return hash;
}


/*	Scans a directory. The second argument tells it what type of scan it is - store or scan.
**	When scan_type is "store", it saves the MD5 hashes of ecah file to the global array hash_n_files.
**	When scan_type is "scan", it calculates the MD5 hash of each file and checks if the hash of a
**	particular file has been modified or not; by comparing with the list of hashes in hash_n_files. If the
**	MD5 hash has changed, it checks for the signature of the virus in that file. If the detection is
**	positive, it prints out the file name and mentions that it is infected.
**	NOTE: This also scans the sub-directories - does a recursive scan of the directory sent to it as argument.
*/
void scan_directory(const char* directory, const scan_t scan_type)
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
		char path [MAX_PATH_LEN];
		snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
				
		if (entry->d_type == DT_DIR)	// It is a directory
		{
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			scan_directory(path, scan_type);
		}
		else							// else, it is a file...
		{
			unsigned char* hash = calc_MD5(path);

			if (scan_type == store)
			{
				size_t prev_size = allocated_size;
				++num_of_files;

				if (allocated_size == 0)
					allocated_size = DEFAULT_ALLOC_SIZE;
				else if (num_of_files > allocated_size)
					allocated_size <<= 1;

				if(prev_size != allocated_size)
					hash_n_files = realloc(hash_n_files, sizeof(char*) * allocated_size);

				hash_n_files[num_of_files - 1] = hash;
			}
			else
			{
				size_t i, str_len = HASH_LEN + strlen(path);

				for(i = 0; i < num_of_files; ++i)
					if(byte_arr_comp(hash, hash_n_files[i], str_len) == 1)
						break;

				if(i == num_of_files && detect_signature(path))
					printf("%s is infected\n", path);

				free(hash);
			}
		}
	}
}


//	Frees the dynamically allocated memory held by hash_n_files.
void free_all(void* args)
{
	int i;
	for(i = 0; i < num_of_files; ++i)
		free(hash_n_files[i]);

	if(hash_n_files != NULL)
		free(hash_n_files);
	printf("Successfully deallocated dynamically allocated memory\n");
}


//	Entry point for the thread. Code is self-explainatory.
void* thread_entry(void* args)
{
	pthread_cleanup_push(free_all, "Frees the dynamically allocated array");
	scan_directory(".", store);		// Store the hashes of all files in the global array hash_n_files.

	while(1)
	{
		sleep(T);					// sleep for T seconds..
		scan_directory(".", scan);	// ..and then scan the directory..
	}								// Do this in an infinite loop, until you get a cancel signal
									// from the main thread.

	pthread_cleanup_pop(0);
	return ((void*) 0);
}


//	Spawns a thread and then waits for the user to press a key.. When the user presses 'Q' or 'q', it cancels the
//	thread and then cleanly exits.
int main()
{
	char c;
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, thread_entry, (void*) NULL);

	while(1)
	{
		c = getchar();
		if(c == 'Q' || c == 'q')
		{
			pthread_cancel(thread_id);
			break;
		}
	}

	pthread_join(thread_id, NULL);
	printf("Joined the thread... Exiting cleanly...\n");
	return 0;
}
