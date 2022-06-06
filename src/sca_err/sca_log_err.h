#ifndef SCA_LOG_ERR_H
#define SCA_LOG_ERR_H

#include "sca_error.h"

/*===========================================================================*/
/* 日志错误 -- author by huowj */
/*===========================================================================*/

#define SCA_ERR_LOG_BASE        (SCA_ERR_BASIC_BUILD(SCA_ERR_LOG))	/* 错误基准	码 */
#define SCA_ERR_LOG_NEW_LOCK    (SCA_ERR_LOG_BASE + 1)              /* 创建互斥锁失败 */
#define SCA_ERR_LOG_OPEN_ICONV  (SCA_ERR_LOG_NEW_LOCK + 1)          /* 打开字符集转码工具失败 */
#define SCA_ERR_LOG_FORMAT      (SCA_ERR_LOG_OPEN_ICONV + 1)        /* 格式化字符串失败 */
#define SCA_ERR_LOG_BUFFER      (SCA_ERR_LOG_FORMAT + 1)            /* 缓冲区不足 */
#define SCA_ERR_LOG_TYPE        (SCA_ERR_LOG_BUFFER + 1)            /* 日志类型错误 */
#define SCA_ERR_LOG_OPEN_FILE   (SCA_ERR_LOG_TYPE + 1)              /* 打开日志文件失败 */

void sca_log_load_err();

/*===========================================================================*/

#endif /* SCA_LOG_ERR_H */
