#include <sca_trace.h>

#include "sca_cmd_help.h"
#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

/* 命令定义表 */
static const char *help_def_list[] = {
    "版本号：./simpleca -version",
    "输入：./simpleca -in xxx.txt -out std",
    "输出：./simpleca -in std -out xxx.txt",
    "生成密钥：./simpleca -genkey",
    NULL
};

int sca_cmd_help(struct sca_cmd_opt *opt)
{
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!opt->arg_num) {
        int i = 0;
        const char *help = NULL;

        while ((help = help_def_list[i++])) {
            SCA_TRACE("%s\n", help);
        }
    }

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/
