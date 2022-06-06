#include <sca_trace.h>

#include "sca_cmd_help.h"
#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

struct help_opt
{
    const char *opt;
    const char *def;
};

/* 命令定义表 */
static struct help_opt help_def_list[] = {
    { CMD_VERSION, "版本号，./simpleca -version" },
    { CMD_INPUT, "输入，./simpleca -in xxx.txt -out std" },
    { CMD_OUTPUT, "输出，./simpleca -in std -out xxx.txt" }
};

/* 获取帮助 */
const char *get_help_opt(const char *opt);

int sca_cmd_help(struct sca_cmd_opt *opt)
{
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!opt->arg_num) {
        int i = 0;
        const struct sca_cmd_opt *def = sca_cmd_find_def_opt("-"CMD_HELP);

        if (!def) {
            SCA_TRACE_CODE(SCA_CMD_ERR_UNKNOWN_ARGS);
            return SCA_CMD_ERR_UNKNOWN_ARGS;
        }

        for (; i < def->arg_num || def->args[i]; i++) {
            const char *str = get_help_opt(def->args[i]);

            if (str) {
                SCA_TRACE("-%s %s\n", def->args[i], str);
            } else {
                SCA_TRACE("-%s 未定义\n", def->args[i]);
            }
        }
    }

    return SCA_ERR_SUCCESS;
}

const char *get_help_opt(const char *opt)
{
    int i = 0;
    int count = 0;

    if (!opt || !*opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return NULL;
    }

    for (count = sizeof(help_def_list) / sizeof(help_def_list[0]); i < count; i++) {
        if (!strcmp(opt, help_def_list[i].opt)) {
            return help_def_list[i].def;
        }
    }

    return NULL;
}

/*===========================================================================*/
