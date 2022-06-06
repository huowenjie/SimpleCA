#ifndef SCA_LINK_ERR_H
#define SCA_LINK_ERR_H

/*===========================================================================*/
/* 链表错误模块 -- author by huowj */
/*===========================================================================*/

#include "sca_error.h"

#define SCA_ERR_LINK_BASE (SCA_ERR_BASIC_BUILD(SCA_ERR_LINK))   /* 错误基准码 */
#define SCA_ERR_LINK_INDEX_RANGE (SCA_ERR_LINK_BASE + 1)        /* 链表索引超出范围 */

void sca_link_load_err();

/*===========================================================================*/

#endif /* SCA_LINK_ERR_H */
