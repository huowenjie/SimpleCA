#ifndef SCA_CMD_HELP_H
#define SCA_CMD_HELP_H

#include "sca_cmd_priority.h"
#include "sca_cmd_io.h"

/*===========================================================================*/
/* 帮助模块 */
/*===========================================================================*/

/* 帮助命令 */
#define CMD_HELP "help"

/* 参数表 */
#define CMD_HELP_ARGS { \
    CMD_VERSION,\
    CMD_INPUT,\
    CMD_OUTPUT,\
    NULL \
}

/* 声明参数表 */
#define CMD_HELP_DECLARE(name) \
    const char *name[] = CMD_HELP_ARGS

/* 内置选项定义 */
#define CMD_HELP_DEF_OPTS(args) { CMD_HELP, args, 0, 1, 0, CMD_PRIORITY_HELP, sca_cmd_help }

/* 帮助 */
int sca_cmd_help(struct sca_cmd_opt *opt);

/*===========================================================================*/

#endif /* SCA_CMD_HELP_H */
