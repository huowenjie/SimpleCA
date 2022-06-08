#include "sca_cmd_err.h"

/*===========================================================================*/

/* 命令错误代码 */
const struct sca_err_info cmd_err_list[] = 
{
    { { SCA_ERR_CMD                 }, "CMD 错误模块" },
    { { SCA_CMD_ERR_BASE            }, "CMD 错误基准码" },
    { { SCA_CMD_ERR_LIST_IS_FULL    }, "指令列表已满" },
    { { SCA_CMD_ERR_UNKNOWN_ARGS    }, "未知的参数" },
    { { SCA_CMD_ERR_INVALID_OPT     }, "无效的选项" },
    { { SCA_CMD_ERR_NO_THIS_OPT     }, "参数不存在" },
    { { SCA_CMD_ERR_ARGS_COUNT      }, "参数数量错误" },
    { { 0 }, NULL }
};

void sca_cmd_load_err()
{
    sca_load_err_list(cmd_err_list);
}

/*===========================================================================*/
