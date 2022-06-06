#ifndef SCA_SCA_CMD_LIST_H
#define SCA_SCA_CMD_LIST_H

#include "sca_cmd_opt.h"

/*===========================================================================*/
/* 命令列表 */
/*===========================================================================*/

typedef struct sca_cmd_list SCA_CMD_LIST;

/* 默认的命令列表 */
SCA_CMD_LIST *sca_cmd_list_def();

/* 初始化命令列表 */
void sca_cmd_list_init(SCA_CMD_LIST *list);

/* 添加命令 */
int sca_cmd_list_push(SCA_CMD_LIST *list, struct sca_cmd_opt *opt);

/* 移除列表末尾命令 */
struct sca_cmd_opt *sca_cmd_list_pop(SCA_CMD_LIST *list);

/* 清空命令 */
int sca_cmd_list_clear(SCA_CMD_LIST *list);

/* 将命令按优先级进行排序 */
int sca_cmd_list_sort(SCA_CMD_LIST *list);

/*===========================================================================*/

#endif /* SCA_SCA_CMD_LIST_H */
