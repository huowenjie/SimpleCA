#ifndef SCA_CMD_TEST_H
#define SCA_CMD_TEST_H

#include "sca_cmd_opt.h"

/*===========================================================================*/
/* 测试 */
/*===========================================================================*/

/* 帮助命令 */
#define CMD_TEST "test"

/* 声明参数表 */
#define CMD_TEST_DECLARE(name) \
    const char *name[] = { NULL }

/* 内置选项定义 */
#define CMD_TEST_DEF_OPTS(args) { CMD_TEST, args, 0, 10, 0, CMD_PRIORITY_TEST, sca_cmd_test }

/* 帮助 */
int sca_cmd_test(struct sca_cmd_opt *opt);

/*===========================================================================*/

#endif /* SCA_CMD_TEST_H */
