#include "sca_hash_err.h"

/*===========================================================================*/

/* hash 错误表 */
static struct sca_err_info hash_err_list[] = {
	{ { SCA_ERR_HASH            }, "散列表错误模块" },
	{ { SCA_ERR_HASH_BASE       }, "错误基准码" },
	{ { SCA_ERR_HASH_NOT_INIT   }, "散列表未初始化" },
	{ { SCA_ERR_HASH_NODE       }, "获取哈希表节点失败" },
	{ { SCA_ERR_HASH_NO_ELEM    }, "元素不存在" },
	{ { 0 }, NULL }
};

void sca_hash_load_err()
{
	sca_load_err_list(hash_err_list);
}

/*===========================================================================*/
