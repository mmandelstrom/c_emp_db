#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "file.h"
#include "parse.h"

void print_usage(char *argv[])
{
	printf("Usage: %s -n -f <database file>\n", argv[0]);
	printf("\t -n - create new database file\n");
	printf("\t -f - (required) path to database file\n");
	printf("\t -p - port\n");
	printf("\t -l - list\n");
	return;
}

int main(int argc, char *argv[])
{
	char *newHours = NULL;
	char *employeeName = NULL;
	char *filepath = NULL;
	char *portarg = NULL;
	char *addstring = NULL;
	unsigned short port = 0;
	bool newfile = false;
	bool list = false;
	int c;
	int dbfd = -1;
	struct dbheader_t *dbhdr = NULL;
	struct employee_t *employees = NULL;

	while ((c = getopt(argc, argv, "nf:a:p:r:h:l")) != -1)
	{
		switch (c)
		{
		case 'n':
			newfile = true;
			break;
		case 'f':
			filepath = optarg;
			break;
		case 'p':
			portarg = optarg;
			break;
		case 'a':
			addstring = optarg;
			break;
		case 'l':
			list = true;
			break;
		case 'r':
			employeeName = optarg;
			break;
		case 'h':
			newHours = optarg;
			break;
		case '?':
			printf("Unknown option -%c\n", c);
			break;
		default:
			return -1;
		}
	}

	if (filepath == NULL)
	{
		printf("Filepath is a required argument\n");
		print_usage(argv);
		return 0;
	}

	if (newfile)
	{
		dbfd = create_db_file(filepath);
		if (dbfd == STATUS_ERROR)
		{
			printf("Unable to create database file\n");
			return -1;
		}
		if (create_db_header(dbfd, &dbhdr) == STATUS_ERROR)
		{
			printf("Unable to create dbheader\n");
			return -1;
		}
	}
	else
	{
		dbfd = open_db_file(filepath);
		if (dbfd == STATUS_ERROR)
		{
			printf("Unable to open database file\n");
			return -1;
		}
		if (validate_db_header(dbfd, &dbhdr) == STATUS_ERROR)
		{
			printf("Failed to validate db header\n");
			return -1;
		}
	}

	if (read_employees(dbfd, dbhdr, &employees) != STATUS_SUCCESS) {
		printf("Unable to read employees\n");
		return 0;
	}


	if (addstring) {
		dbhdr->count++;
		struct employee_t *temp = realloc(employees, dbhdr->count * (sizeof(struct employee_t)));
		if (employees == NULL) {
			printf("Failed to reallocate memory for new employee\n");
 			return 0;
		}
		employees = temp;
		add_employee(dbhdr, employees, addstring);
	}

	if (list) {
		list_employees(dbhdr, employees);
	}

	if (employeeName) {
		if (remove_employee(dbhdr, employees, employeeName) != STATUS_SUCCESS) {
	     		printf("Unable to delete employee: %s\n", employeeName);
			return 0;
		}
		
		dbhdr->count--;
		struct employee_t *temp = realloc(employees, dbhdr->count * (sizeof(struct employee_t)));
		if (temp == NULL) {
			printf("Failed to create temporary array while removing employee\n");
			return STATUS_ERROR;
		}
		employees = temp;
	}

	if (newHours) {
		if (update_hours(dbhdr, employees, newHours) != STATUS_SUCCESS) {
			printf("Unable to update hours\n");
			return 0;
		}
	}

  

	output_file(dbfd, dbhdr, employees);


	return 0;
}
