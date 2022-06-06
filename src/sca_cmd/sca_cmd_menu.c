#include <stdio.h>
#include <string.h>
#include <sca_trace.h>

#include "sca_cmd_menu.h"

/*===========================================================================*/

#define STR_BUFF_MAX 256

const char *input_str(const char *hint, const char *def)
{
    static char buff[STR_BUFF_MAX] = { 0 };
    char *ch = NULL;

    if (hint && hint[0]) {
        SCA_TRACE("%s\n", hint);
    }

    if (!fgets(buff, STR_BUFF_MAX, stdin)) {
        return NULL;
    }

    ch = strrchr(buff, '\n');
    
    if (*ch) {
        *ch = 0;
    }

    if (!strlen(buff) && def && def[0]) {
        strncpy(buff, def, STR_BUFF_MAX);
        buff[STR_BUFF_MAX - 1] = 0;
    }

    return buff;
}

int input_int(const char *hint, int def)
{
    static char buff[STR_BUFF_MAX] = { 0 };
    char *ch = NULL;
    int ret = -1;
    int fields = 0;

    if (hint && hint[0]) {
        SCA_TRACE("%s\n", hint);
    }

    if (!fgets(buff, STR_BUFF_MAX, stdin)) {
        return -1;
    }

    ch = strrchr(buff, '\n');
    
    if (*ch) {
        *ch = 0;
    }

    if (!strlen(buff)) {
        return def;
    }

    ret = -1;

    if (buff[0] == '0' && buff[1] == 'x') {
        ch = buff + 2;
        fields = sscanf(buff, "%X", &ret);
    } else {
        fields = sscanf(buff, "%d", &ret);
    }

    return (fields > 0) ? ret : -1;
}

void show_menu(const char * const * menu, int count)
{
    int i = 0;

    if (!menu || count < 1) {
        return;
    }

    SCA_TRACE("\n");
    SCA_TRACE("%s\n", "========================================");
    SCA_TRACE("%s\n", menu[0]);
    SCA_TRACE("%s\n", "========================================");

    for (i = 1; i < count; i++) {
        SCA_TRACE("%s\n", menu[i]);
    }

    SCA_TRACE("%s\n", "----------------------------------------");
    SCA_TRACE("\n");
}

int select_menu(const char * const * menu, int count, int def)
{
    if (!menu || count < 2) {
        return -1;
    }

    show_menu(menu, count);
    return input_int("ÇëÑ¡Ôñ:", def);
}

/*===========================================================================*/
