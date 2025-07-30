#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "parse.h"

void list_employees(struct dbheader_t *dbhdr, struct employee_t *employees) {

}

int add_employee(struct dbheader_t *dbhdr, struct employee_t *employees, char *addstring) { 
   


}

int read_employees(int fd, struct dbheader_t *dbhdr, struct employee_t **employeesOut) {

}

// lägg till strcut t employee
int output_file(int fd, struct dbheader_t *dbhdr) {
if (fd < 0) {
printf("Recieved bad FD\n");
return STATUS_ERROR;
}

dbhdr->magic = htonl(dbhdr->magic);
dbhdr->filesize = htonl(dbhdr->filesize);
dbhdr->version = htons(dbhdr->version);
dbhdr->count = htons(dbhdr->count);

lseek(fd, 0, SEEK_SET);

 if (write(fd, dbhdr, sizeof(struct dbheader_t)) == -1) {
perror("write");
return STATUS_ERROR;
}

return STATUS_SUCCESS;

}

int validate_db_header(int fd, struct dbheader_t **headerOut) {
if (fd == -1) {
printf("Recieved bad FD\n");
return STATUS_ERROR; 
}

struct dbheader_t *header = calloc(1, sizeof(struct dbheader_t));
if (header == NULL) {
printf("Calloc failed to create dbheader\n");
return STATUS_ERROR;
}


if (read(fd, header, sizeof(struct dbheader_t)) != sizeof(struct dbheader_t)) {
perror("read");
free(header);
return STATUS_ERROR;
}

header->magic = ntohl(header->magic);
header->filesize = ntohl(header->filesize);
header->version = ntohs(header->version);
header->count = ntohs(header->count);

if (header->magic != HEADER_MAGIC) {
printf("Improper header magic\n");
free(header);
return -1;
}

if (header->version != 1) {
printf("Improper header version\n");
free(header);
return -1;
}

struct stat dbstat = {0};
fstat(fd, &dbstat);
if (header->filesize != dbstat.st_size) {
printf("Corrupt database file\n");
free(header);
return -1;
}

*headerOut = header;

return STATUS_SUCCESS;
}

int create_db_header(int fd, struct dbheader_t **headerOut) {
struct dbheader_t *header = calloc(1, sizeof(struct dbheader_t));
if (header == NULL) {
printf("Calloc failed to create header\n");
return STATUS_ERROR;
}

header->magic = HEADER_MAGIC;
header->version = 0x1;
header->count = 0;
header->filesize = sizeof(struct dbheader_t);

*headerOut = header;

return STATUS_SUCCESS;
}


