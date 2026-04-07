#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_FILE "passwords.txt"
#define MAX 256

void generate_password(char *output, int length)
{
    FILE *fp;
    char buffer[MAX];
    char command[MAX];

    snprintf(command, sizeof(command), "echo %d | ./passgen", length); //calls the assembly function and connects it between assembly and C program
    fp = popen(command, "r");

    if (fp == NULL)
    {
        strncpy(output, "ERROR", MAX);
        return;
    }
//capturing the generated password
    if (fgets(buffer, sizeof(buffer), fp))
    {
        buffer[strcspn(buffer, "\r\n")] = 0; //omitting the newline
        char *pwd_start = strstr(buffer, "Generated password: ");
        if (pwd_start) {
            strncpy(output, pwd_start + 20, MAX); 
        } else {
            strncpy(output, buffer, MAX);
        }
    }

    pclose(fp);
}

void store_password(const char *email, const char *password)
{
    FILE *fp = fopen(DB_FILE, "a");

    if (!fp)
    {
        return;
    }

    if (lockf(fileno(fp), F_LOCK, 0) == 0)
    {
        fprintf(fp, "%s|%s\n", email, password);
        lockf(fileno(fp), F_ULOCK, 0);
    }
    
    fclose(fp);
}

int search_password(const char *email, char *password)
{
    FILE *fp = fopen(DB_FILE, "r");
    char line[MAX * 2], file_email[MAX], file_pass[MAX];

    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, "%255[^|]|%255s", file_email, file_pass) == 2)
        {
            if (strcmp(email, file_email) == 0)
            {
                strncpy(password, file_pass, MAX);
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

void create_entry(const char *email, int length)
{
    char password[MAX];

    generate_password(password, length);
    store_password(email, password);

    printf("%s\n", password);
}

void find_entry(const char *email)
{
    char password[MAX];

    if (search_password(email, password))
        printf("%s\n", password);
    else
        printf("NOT_FOUND\n");
}

int main()
{
    int choice, length;
    char email[MAX];

    if (scanf("%d", &choice) != 1) return 1;
    if (scanf("%255s", email) != 1) return 1;

    if (choice == 1)
    {
        if (scanf("%d", &length) != 1) length = 16;
        create_entry(email, length);
    }
    else
    {
        find_entry(email);
    }

    return 0;
}
