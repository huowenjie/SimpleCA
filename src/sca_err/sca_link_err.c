#include "sca_link_err.h"

/* 日志错误表 */
static struct sca_err_info link_err_list[] = {
	{ { SCA_ERR_LINK             }, "链表模块错误表" },
	{ { SCA_ERR_LINK_BASE        }, "错误基准码" },
	{ { SCA_ERR_LINK_INDEX_RANGE }, "链表索引超出范围" },
	{ { 0 }, NULL }
};

void sca_link_load_err()
{
	sca_load_err_list(link_err_list);
}
