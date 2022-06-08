#ifndef SCA_CMD_HELP_H
#define SCA_CMD_HELP_H

#include "sca_cmd_priority.h"
#include "sca_cmd_io.h"
#include "sca_cmd_genkey.h"

/*===========================================================================*/
/* 帮助模块 */
/*===========================================================================*/

/* 帮助命令 */
#define CMD_HELP "help"

/* 内置选项定义 */
#define CMD_HELP_DEF_OPTS { CMD_HELP, NULL, 0, 1, 0, CMD_PRIORITY_HELP, sca_cmd_help }

/* 帮助 */
int sca_cmd_help(struct sca_cmd_opt *opt);

/*===========================================================================*/

#endif /* SCA_CMD_HELP_H */
