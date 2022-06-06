#ifndef SCA_SCA_CMD_ERR_H
#define SCA_SCA_CMD_ERR_H

#include <sca_error.h>

/*===========================================================================*/
/* 命令错误模块 */
/*===========================================================================*/

/* 错误基准码 */
#define SCA_CMD_ERR_BASE (SCA_ERR_BASIC_BUILD(SCA_ERR_CMD))

/* 错误代码 */
#define SCA_CMD_ERR_LIST_IS_FULL    (SCA_CMD_ERR_BASE + 1)          /* 列表已满 */
#define SCA_CMD_ERR_UNKNOWN_ARGS    (SCA_CMD_ERR_LIST_IS_FULL + 1)  /* 未知的参数 */
#define SCA_CMD_ERR_INVALID_OPT     (SCA_CMD_ERR_UNKNOWN_ARGS + 1)  /* 无效的选项 */
#define SCA_CMD_ERR_NO_THIS_OPT     (SCA_CMD_ERR_INVALID_OPT + 1)   /* 参数不存在 */
#define SCA_CMD_ERR_ARGS_COUNT      (SCA_CMD_ERR_NO_THIS_OPT + 1)   /* 参数数量错误 */

/* 加载错误模块 */
void sca_cmd_load_err();

/*===========================================================================*/

#endif /* SCA_SCA_CMD_ERR_H */
