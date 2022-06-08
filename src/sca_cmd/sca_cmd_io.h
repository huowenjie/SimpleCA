#ifndef SCA_CMD_IO_H
#define SCA_CMD_IO_H

#include "sca_cmd_priority.h"

/*===========================================================================*/
/* 输入/输出命令 */
/*===========================================================================*/

/* 输入命令 */
#define CMD_INPUT "in"

/* 输出命令 */
#define CMD_OUTPUT "out"

/* 标准输入输出指令 */
#define CMD_IO_STD "std"

/* 命令定义，输入命令的优先级远大于输出命令 */
#define CMD_INPUT_DEF_OPTS { CMD_INPUT, NULL, 0, 1, 1, CMD_PRIORITY_INPUT, sca_cmd_input }
#define CMD_OUTPUT_DEF_OPTS { CMD_OUTPUT, NULL, 0, 1, 1, CMD_PRIORITY_OUTPUT, sca_cmd_output }

/* 输入操作 */
int sca_cmd_input(struct sca_cmd_opt *opt);

/* 输出操作 */
int sca_cmd_output(struct sca_cmd_opt *opt);

/*===========================================================================*/

#endif /* SCA_CMD_IO_H */