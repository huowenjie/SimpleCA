#include "sca_log_err.h"

/* 日志错误表 */
static struct sca_err_info log_err_list[] = {
	{ { SCA_ERR_LOG             }, "日志错误表" },
	{ { SCA_ERR_LOG_BASE        }, "错误基准码" },
	{ { SCA_ERR_LOG_NEW_LOCK    },	"创建互斥锁失败" },
	{ { SCA_ERR_LOG_OPEN_ICONV  }, "打开字符集转码工具失败" },
	{ { SCA_ERR_LOG_FORMAT      }, "格式化字符串失败" },
	{ { SCA_ERR_LOG_BUFFER      }, "缓冲区长度不足" },
	{ { SCA_ERR_LOG_TYPE        }, "日志类型错误" },
	{ { SCA_ERR_LOG_OPEN_FILE   }, "打开日志文件失败" },
	{ { 0 }, NULL }
};

void sca_log_load_err()
{
	sca_load_err_list(log_err_list);
}
