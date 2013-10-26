#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "common.h"

#define INI_MAX_LINE 256
#define MAX_SECTION 32
#define MAX_NAME 128

static unsigned char LISTEN_IP[MAX_NAME] = "127.0.0.1";
static unsigned long LISTEN_PORT = 8888;

static unsigned char GAE_APPIDS[MAX_NAME] = "";
static unsigned char GAE_PASSWORD[MAX_NAME] = "";
static unsigned char GAE_PATH[MAX_NAME] = "";
static unsigned char GAE_PROFILE[MAX_NAME] = "google_cn";
static unsigned int GAE_CRLF = 1;
static unsigned int GAE_VALIDATE = 0;
static unsigned int GAE_OBFUSCATE = 0;

static unsigned char GOOGLE_MODE[MAX_NAME] = "https";

/* Strip whitespace chars off end of given string, in place. Return s. */
static char* rstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char* lskip(const char* s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return (char*)s;
}

/* Return pointer to first char c or ';' comment in given string, or pointer to
   null at end of string if neither found. ';' must be prefixed by a whitespace
   character to register as a comment. */
static char* find_char_or_comment(const char* s, char c)
{
    int was_whitespace = 0;
    while (*s && *s != c && !(was_whitespace && *s == ';')) {
        was_whitespace = isspace((unsigned char)(*s));
        s++;
    }
    return (char*)s;
}

/* See documentation in header file. */
static int ini_parse_file(FILE* file, const unsigned char* section,
                   const unsigned char* name, unsigned char* value)
{
    char line[INI_MAX_LINE];
    char* start;
    char* end;
    int prev_name = 0;

    if (fseek(file, 0, SEEK_SET))
        return -1;
    /* Scan through file line by line */
    while (fgets(line, INI_MAX_LINE, file) != NULL) {

        start = line;
        start = lskip(rstrip(start));

        if (*start == ';' || *start == '\0');
        else if (*start == '[') {
            /* A "[section]" line */
            end = find_char_or_comment(start + 1, ']');
            if (*end == ']') {
                *end = '\0';
                if (!strcmp(section, start + 1))
                    prev_name = 1;
                else
                    prev_name = 0;
            }
            else
                prev_name = 0;
        }
        else if (prev_name) {
            /* Not a comment */
            end = find_char_or_comment(start, '=');
            if (*end == '=') {
                *end = '\0';
                start = rstrip(start);
                if (!strcmp(name, start)) {
                    start = lskip(end + 1);
                    end = find_char_or_comment(start, '\0');
                    if (*end == ';')
                        *end = '\0';
                    rstrip(start);
                    strncpy(value, start, MAX_NAME);
                    value[MAX_NAME - 1] = '\0';
                    return 0;
                }
            }
        }
    }
    return -1;
}

static void config_get(FILE* file, const unsigned char* section,
                const unsigned char* name, unsigned char* value)
{
    if (ini_parse_file(file, section, name, value))
        printf("Initializing '%s' faild. Using default '%s' instead.\n", name, value);
}

static void config_getint(FILE* file, const unsigned char* section,
                const unsigned char* name, unsigned int* value)
{
    unsigned char preload[MAX_NAME];
    if (ini_parse_file(file, section, name, preload))
        printf("Initializing '%s' faild. Using default '%d' instead.\n", name, *value);
    else if (isdigit(*preload))
        *value = atoi(preload);
    else
        printf("Cannot switch on a value of type String. Only int values are permitted.\n");
}

/* See documentation in header file. */
static int ini_parse(const char* filename)
{
    FILE* file;

    file = fopen(filename, "r");
    if (!file)
        return -1;
    config_get(file, "listen", "ip", LISTEN_IP);
    config_getint(file, "listen", "port", &LISTEN_PORT);

    config_get(file, "gae", "appid", GAE_APPIDS);
    config_get(file, "gae", "password", GAE_PASSWORD);
    config_get(file, "gae", "path", GAE_PATH);
    config_get(file, "gae", "profile", GAE_PROFILE);
    config_getint(file, "gae", "crlf", &GAE_CRLF);
    config_getint(file, "gae", "obfuscate", &GAE_VALIDATE);
    config_getint(file, "gae", "validate", &GAE_OBFUSCATE);

    config_get(file, GAE_PROFILE, "mode", GOOGLE_MODE);

    fclose(file);
    return 0;
}

static int info(const char* filename)
{
    if (ini_parse(filename)) {
        printf("Terminal failure: Unable to open file '%s'.\n", filename);
        return -1;
    }
    printf("\n");
    printf("------------------------------------------------------\n");
    printf("GoAgent Version    : special\n");
    printf("Listen Address     : %s:%d\n", LISTEN_IP, LISTEN_PORT);
    printf("GAE Mode           : %s\n", GOOGLE_MODE);
    printf("GAE Profile        : %s\n", GAE_PROFILE);
    printf("GAE APPID          : %s\n", GAE_APPIDS);
    printf("------------------------------------------------------\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 ? info("config.ini") : info(argv[1]))
        printf("Usage: %s [FILE]\n", argv[0]);
    return 0;
}
