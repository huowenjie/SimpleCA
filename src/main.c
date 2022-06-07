#include <sca_trace.h>
#include <sca_error.h>

#include "sca_cmd/sca_cmd_opt.h"
#include "sca_cmd/sca_cmd_buf.h"

/*===========================================================================*/

int main(int argc, char *argv[])
{
	sca_load_all_err();

	SCA_TRACE_START;

	SCA_TRACE_LEVEL_DEBUG;
	SCA_TRACE_OUTPUT_STD;
    SCA_TRACE_SHOW_DEF;

    /* 创建全局缓冲区 */
    sca_cmd_buf_start();
    sca_cmd_buf_create(SCA_BUF_NAME_IO, 0);

    /*---------------------------------------------------*/

	/* 解析命令选项 */
	sca_cmd_opt_parse(argc, (const char **)argv);

    /*---------------------------------------------------*/

    /* 销毁全局缓冲区 */
    sca_cmd_buf_destroy(SCA_BUF_NAME_IO);
    sca_cmd_buf_end();

	/* 释放日志系统 */
	SCA_TRACE_END;
	return 0;
}

/*===========================================================================*/
