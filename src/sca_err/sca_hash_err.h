#ifndef SCA_HASH_ERR_H
#define SCA_HASH_ERR_H

#include "sca_error.h"

/*===========================================================================*/
/* 散列表错误码 */
/*===========================================================================*/

#define SCA_ERR_HASH_BASE (SCA_ERR_BASIC_BUILD(SCA_ERR_HASH))	/* 错误基准	码 */
#define SCA_ERR_HASH_NOT_INIT (SCA_ERR_HASH_BASE + 1)           /* 哈希表未初始化 */
#define SCA_ERR_HASH_NODE (SCA_ERR_HASH_NOT_INIT + 1)           /* 获取哈希表节点失败 */
#define SCA_ERR_HASH_NO_ELEM (SCA_ERR_HASH_NODE + 1)            /* 元素不存在 */

void sca_hash_load_err();

/*===========================================================================*/

#endif /* SCA_HASH_ERR_H */
