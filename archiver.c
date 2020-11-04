// Copyright Dalimon Iarina 312CA
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>

union record {
    char charptr[512];
    struct header {
        char name[100];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char chksum[8];
        char typeflag;
        char linkname[100];
        char magic[8];
        char uname[32];
        char gname[32];
        char devmajor[8];
        char devminor[8];
    } header;
};

int number_of_parameters(char com[50]) { // calculeaza nr parametrilor comenzii
    int nr = 0;
    char copy[50];
    char *token;
    strcpy(copy, com);
    token = strtok(copy, " ");
    while (token != NULL) {
        nr++;
        token = strtok(NULL, " ");
    }
    return nr;
}

void read_command(char com[50], char command[8]) { // citeste numele comenzii
    char copy[50];
    char *token;
    strcpy(copy, com);
    token = strtok(copy, " ");
    strcpy(command, token);
}

/* fct de mai jos verifica daca comanda este cunoscura
si daca nr de param este cel corect */

int verify_command(char com[50]) {
    int nr, verify = 0;
    char copy[50];
    char *token;
    strcpy(copy, com);
    nr = number_of_parameters(com);
    token = strtok(copy, " ");
    if ((strcmp(token, "create") == 0) || (strcmp(token, "extract") == 0)) {
        if (nr != 3) {
            verify = 1;
        }
    } else if (strcmp(token, "list") == 0) {
        if (nr != 2) {
            verify = 1;
        }
    } else if (strcmp(token, "exit") == 0) {
        if (nr != 1) {
            verify = 1;
        }
    } else {
        verify = 1;
    }
    return verify;
}

// fct de mai jos citeste parametrii comenzii create
void read_create(char com[50], char archive[50], char directory[50]) {
    char copy[50];
    char *token;
    strcpy(copy, com);
    token = strtok(copy, " ");
    token = strtok(NULL, " ");
    strcpy(archive, token); // nume arhiva
    token = strtok(NULL, " ");
    strcpy(directory, token); // nume director
    directory[strlen(directory) - 1] = '\0'; // elimin \n de la final
}

void read_list(char com[50], char archive[50]) {
    char copy[50];
    char *token;
    strcpy(copy, com);
    token = strtok(copy, " ");
    token = strtok(NULL, " ");
    strcpy(archive, token); // nume arhiva
    archive[strlen(archive) - 1] = '\0'; // elimin \n de la final
}

void read_extract(char com[50], char archive[50], char file[50]) {
    char copy[50];
    char *token;
    strcpy(copy, com);
    token = strtok(copy, " ");
    token = strtok(NULL, " ");
    strcpy(archive, token); // nume arhiva
    token = strtok(NULL, " ");
    strcpy(file, token); // nume fisier
    file[strlen(file) - 1] = '\0'; // elimin \n de la final
}

// fct de mai jos fac comanda create
int fct_permissions(char x[4]) { // calc permisiuni (ugo)
    int mode_1, i, n;
    mode_1 = 0;
    n = strlen(x);
    for (i = 0; i < n; i++) {
        if (x[i] == 'r') {
            mode_1 += 4;
        } else if (x[i] == 'w') {
            mode_1 += 2;
        } else if (x[i] == 'x') {
            mode_1 += 1;
        }
    }
    return mode_1;
}

int fct_uid(char name[6]) {
    FILE *file_2 = fopen("usermap.txt", "r");
    char *line_2 = NULL;
    size_t len_2 = 0;
    ssize_t read;
    char *p;
    int nr_uid;
    char uid[8];
    read = getline(&line_2, &len_2, file_2);
    while (read != -1) {
        p = strtok(line_2, ":");
        if (strcmp(name, p) == 0) {
            p = strtok(NULL, ":");
            p = strtok(NULL, ":"); // aici gasesc uid
            strcpy(uid, p);
            nr_uid = atoi(uid);
        }
        read = getline(&line_2, &len_2, file_2);
    }
    fclose(file_2);
    free(line_2);
    return nr_uid;
}

int fct_gid(char name[6]) {
    FILE *file_2 = fopen("usermap.txt", "r");
    char *line_2 = NULL;
    size_t len_2 = 0;
    ssize_t read;
    char *p;
    int nr_gid;
    char gid[8];
    read = getline(&line_2, &len_2, file_2);
    while (read != -1) {
        p = strtok(line_2, ":");
        if (strcmp(name, p) == 0) {
            p = strtok(NULL, ":");
            p = strtok(NULL, ":");
            p = strtok(NULL, ":"); // aici gasesc gid
            strcpy(gid, p);
            nr_gid = atoi(gid);
        }

        read = getline(&line_2, &len_2, file_2);
    }
    fclose(file_2);
    free(line_2);
    return nr_gid;
}

void command_create(char archive[30]) {
    union record record;
    struct tm tm;
    time_t t;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char q;
    int k, nr_uid, nr_gid, dimension, i, size_2;
    long sum;
    char *p, permissions_owner[4], permissions_group[4], permissions_others[4];
    char year[5], month[3], day[3], hour[3], minits[3], seconds[3], buf[2];
    char permissions[11], date[11], mode_2[8], mode_3[4], uid_1[8];
    char chksum_1[8], size_1[12], gid_1[8];
    record.header.typeflag = '\0';
    memset(record.header.devmajor, '\0', 8);
    memset(record.header.devminor, '\0', 8);
    FILE *file = fopen("files.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "> Failed!\n");
        exit(-1);
    } else {
        fprintf(stderr, "> Done!\n");
    }
    FILE *files_3 = fopen(archive, "wb");

    read = getline(&line, &len, file);
    while (read != -1) {
        sum = 0;
        memset(record.header.name, '\0', 100);
        memset(record.header.linkname, '\0', 100);
        memset(record.header.uname, '\0', 32);
        memset(record.header.gname, '\0', 32);
        memset(record.header.size, '\0', 12);
        memset(record.header.uid, '\0', 8);
        memset(record.header.gid, '\0', 8);
        memset(record.charptr, '\0', 512);
        strcpy(record.header.magic, "GNUtar ");
        memset(record.header.chksum, ' ', 8);

        k = 0;
        strcpy(mode_2, "0000");
        p = strtok(line, " :+");
        while (p != NULL) {
            if (k == 0) {
                strcpy(permissions, p);
                strcpy(permissions, permissions + 1);
                strncpy(permissions_owner, permissions, 3);
                permissions_owner[3] = '\0';
                sprintf(buf, "%d", fct_permissions(permissions_owner));
                strcat(mode_2, buf);
                strcpy(permissions, permissions + 3);
                strcpy(permissions_group, permissions + 3);
                permissions_group[3] = '\0';
                sprintf(buf, "%d", fct_permissions(permissions_group));
                strcat(mode_2, buf);
                strcpy(permissions, permissions + 3);
                strcpy(permissions_others, permissions);
                sprintf(buf, "%d", fct_permissions(permissions_others));
                strcat(mode_2, buf);
                strcpy(record.header.mode, "0000");
                sprintf(mode_3, "%d", atoi(mode_2));
                strcat(record.header.mode, mode_3);
            } else if (k == 2) {
                strcpy(record.header.uname, p);
            } else if (k == 3) {
                strcpy(record.header.gname, p);
            } else if (k == 4) {
                size_2 = atoi(p);
                sprintf(size_1, "%o", atoi(p));
                for (i = (strlen(size_1) + 1); i < 12; i++) {
                    strcat(record.header.size, "0");
                }
                strcat(record.header.size, size_1);
            } else if (k == 5) {
                strcpy(date, p);
                strncpy(year, date, 4);
                year[5] = '\0';
                strcpy(date, date + 5);
                strncpy(month, date, 2);
                month[3] = '\0';
                strcpy(date, date + 3);
                strcpy(day, date);
            } else if (k == 6) {
                strcpy(hour, p);
            } else if (k == 7) {
                strcpy(minits, p);
            } else if (k == 8) {
                strncpy(seconds, p, 2);
                seconds[2] = '\0';
            } else if (k == 10) {
                strcpy(record.header.name, p);
                record.header.name[strlen(record.header.name) - 1] = '\0';
                strcpy(record.header.linkname, record.header.name);
            }
            p = strtok(NULL, " +:");
            k++;
        }
        nr_uid = fct_uid(record.header.uname);
        sprintf(uid_1, "%o", nr_uid);
        for (i = (strlen(uid_1) + 1); i < 8; i++) {
            strcat(record.header.uid, "0");
        }

        strcat(record.header.uid, uid_1);

        nr_gid = fct_gid(record.header.uname);
        sprintf(gid_1, "%o", nr_gid);
        for (i = (strlen(gid_1) + 1); i < 8; i++) {
            strcat(record.header.gid, "0");
        }
        strcat(record.header.gid, gid_1);

        // aici incepe mtime
        tm.tm_year = atoi(year) - 1900;
        tm.tm_mon = atoi(month) - 1;
        tm.tm_mday = atoi(day);
        tm.tm_hour = atoi(hour);
        tm.tm_min = atoi(minits);
        tm.tm_sec = atoi(seconds);
        tm.tm_isdst = -1;
        t = mktime(&tm);
        sprintf(record.header.mtime, "%lo", t);

        // aici incepe chksum
        for (i = 0; i < 512; i++) {
            sum += record.charptr[i];
        }

        sprintf(chksum_1, "%07lo", sum);
        record.header.chksum[0] = '0';
        strcpy(record.header.chksum+1, chksum_1);

        // aici includ header-ul in arhiva
        fwrite(&record, sizeof(record), 1, files_3);

        // aici includ fisierele in arhiva
        FILE *files_4 = fopen(record.header.name, "rb");
        fread(&q, sizeof(char), 1, files_4);
        while (!feof(files_4)) {
            fwrite(&q, sizeof(char), 1, files_3);
            fread(&q, sizeof(char), 1, files_4);
        }
        fclose(files_4);

        // aici includ \0 pana marimea fisierului e multiplu de 512
        q = '\0';
        if ((size_2 % 512) != 0) {
            dimension = (size_2 / 512);
            dimension++;
            dimension *= 512;
            for (i = size_2; i < dimension; i++) {
                fwrite(&q, sizeof(char), 1, files_3);
            }
        }
        read = getline(&line, &len, file);
    }

    // aici intruduc \0 de final
    for (i = 0; i < 512; i++) {
        fwrite(&q, sizeof(char), 1, files_3);
    }

    fclose(files_3);
    fclose(file);
    free(line);
}

// fct de mai jos sunt pt list
long power(long n, long k) {
    long x;
    x = n;
    if ( k ==1 ) {
        return x;
    } else {
        return n * power(n, k - 1);
    }
}

long octal_to_decimal(long x) { // schimb size din baza 8 in baza 10
    long nr_baza_10 = 0, nr_power = 8, position = 0;
    while (x != 0) {
        if (position != 0) {
            nr_baza_10 += ((x % 10) * power(nr_power, position));
        } else {
            nr_baza_10 += (x % 10);
        }
        x /= 10;
        position++;
    }
    return nr_baza_10;
}

void command_list(char archive[30]) {
    union record record;
    long position, dimension, size_1, finish;
    FILE *files = fopen(archive, "rb");
    position = 512;
    if (files == NULL) {
        fprintf(stderr, "> File not found!\n");
    } else {
        fseek(files, -512, SEEK_END);
        finish = ftell(files);
        fseek(files, 0, SEEK_SET);
        fread(&record, sizeof(union record), 1, files);
        position = ftell(files);
        if (position == finish) { // cand e doar un fisier in arhiva
            printf("> %s\n", record.header.name);
        }
        while (position < finish) {
            printf("> %s\n", record.header.name);
            size_1 = atoi(record.header.size);
            dimension = (octal_to_decimal(size_1) / 512);
            dimension++;
            dimension *= 512;
            position = ftell(files);
            position += dimension;
            fseek(files, position, SEEK_SET);
            fread(&record, sizeof(union record), 1, files);
        }
        fclose(files);
    }
}

// aici realizez comanda extract
void command_extract(char archive[30], char file_name[100]) {
    union record record;
    long size_1;
    char q;
    int position, dimension, i;
    char new_name[40];
    FILE *files = fopen(archive, "rb");
    if (files == NULL) {
        fprintf(stderr, "> File not found!\n");
        exit(-1);
    } else {
        printf("> File extracted!\n");
        while (!feof(files)) {
            fread(&record, sizeof(union record), 1, files);
            if (strcmp("", record.header.name) == 0) {
                break;
            }
            size_1 = atoi(record.header.size);

            if (strcmp(file_name, record.header.name) == 0) {
                strcpy(new_name, "extracted_"); // creez numele noului fisier
                strcat(new_name, record.header.name);
                FILE *file_1 = fopen(new_name, "wb");
                fread(&q, sizeof(char), 1, files);
                for (i = 0; i < (octal_to_decimal(size_1)); i++) {
                    fwrite(&q, sizeof(char), 1, file_1); // scriu in fisier nou
                    fread(&q, sizeof(char), 1, files); // citesc din arhiva
                }
                fclose(file_1);
                fseek(files, -octal_to_decimal(size_1), SEEK_CUR);
            }
            if (size_1 != 0) { // sar la urmatorul header
                position = ftell(files);
                dimension = ((octal_to_decimal(size_1)) / 512);
                dimension++;
                dimension *= 512;
                position += dimension;
           	    fseek(files, position, SEEK_SET);
            }
        }
    }
    fclose(files);
}

int main() {
    int verify;
    char command[8], archive[30] = " ", directory[30] = " ", com[50], file[50];
    fgets(com, 50, stdin); // pastrez intentionat \n ca sa verific exit
    read_command(com, command);
    while (strcmp(command, "exit\n") != 0) {
        verify = verify_command(com);
        if (verify == 1) {
            printf("> Wrong command!\n");
        } else {
            if (strcmp(command, "create") == 0) {
                read_create(com, archive, directory);
                command_create(archive);
            } else if (strcmp(command, "list") == 0) {
                read_list(com, archive);
                command_list(archive);
            } else {
                read_extract(com, file, archive);
                command_extract(archive, file);
            }
        }
        fgets(com, 50, stdin);
        read_command(com, command);
    }
    return 0;
}
