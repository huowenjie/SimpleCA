#include <sca_error.h>

#include "sca_log_err.h"
#include "sca_link_err.h"
#include "sca_hash_err.h"

/*===========================================================================*/

/* 全局错误模块列表，最多 256 个 */
static const struct sca_err_info *err_module_list[SCA_ERR_MAX_MODULES] = { 0 };

/* 通用错误列表 */
static struct sca_err_info comm_err_list[] = {
	{ { SCA_ERR_COMMON          }, "通用错误表"	},
	{ { SCA_ERR_BASE            }, "错误基准码"	},
	{ { SCA_ERR_FAILED          }, "失败" },
	{ { SCA_ERR_PARAM           }, "参数错误" },
	{ { SCA_ERR_NULL_PARAM      }, "空参数错误"	},
	{ { SCA_ERR_NULL_POINTER    }, "空指针错误"	},
	{ { SCA_ERR_NULL_STRING     }, "空的字符串"	},
	{ { 0 }, NULL }
};

static const char *unknow_errs[] = {
	"未知的错误，错误列表未加载",
	"未知的错误"
};

const char *sca_err_desc(SCA_UINT32 code)
{
	SCA_UINT32 i = 0;
	const struct sca_err_info *err_list = NULL;
	SCA_UINT32 mod = SCA_ERR_MOD_RECOVER(code) - 1;

	if (mod > SCA_ERR_MAX_MODULES - 1) {
		return unknow_errs[1];
	}

	err_list = err_module_list[mod];
	if (!err_list) {
		return unknow_errs[0];
	}

	/* 线性检索错误描述，当然数据量大的话这里可以
	   用 hash 表来优化 */
	while (err_list[i].desc || err_list[i].err_id.code) {
		if (err_list[i].err_id.code == code) {
			return err_list[i].desc;
		}

		i++;
	}

	return unknow_errs[1];
}

const char *sca_err_mod_desc(SCA_UINT32 code)
{
	SCA_UINT32 mod = SCA_ERR_MOD_RECOVER(code) - 1;
	const struct sca_err_info *err_list = NULL;

	if (mod > SCA_ERR_MAX_MODULES - 1) {
		return unknow_errs[1];
	}

	err_list = err_module_list[mod];
	if (!err_list) {
		return NULL;
	}

	return err_list[0].desc;
}

void sca_load_all_err()
{
	/* 加载通用错误列表 */
	sca_load_err_list(comm_err_list);

	/* 加载链表模块错误表 */
	sca_link_load_err();

	/* 加载日志模块错误列表 */
	sca_log_load_err();

    /* 加载 hash 模块错误列表 */
	sca_hash_load_err();
}

void sca_load_err_list(const struct sca_err_info *list)
{
	SCA_UINT32 module = 0;

	if (!list) {
		return;
	}

	module = list[0].err_id.module - 1;

	if (module > SCA_ERR_MAX_MODULES) {
		return;
	}

	/* 确保不会覆盖其他的表 */
	if (!err_module_list[module]) {
		err_module_list[module] = list;
	}
}

void sca_unload_err_list(SCA_UINT32 module)
{
	/* 确保不会出现野指针 */
	if (err_module_list[module])
	{
		err_module_list[module] = NULL;
	}
}

/*===========================================================================*/
