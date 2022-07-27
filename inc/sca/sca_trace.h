#ifndef SCA_TRACE_H
#define SCA_TRACE_H

#include "sca_log.h"

/*===========================================================================*/
/* 追踪系统快速定义 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

LOG_TRACE_DECLARE(sca_trace)

#define SCA_TRACE_START          sca_trace_new()
#define SCA_TRACE_END            sca_trace_free()

#define SCA_TRACE_LEVEL(level)   sca_trace_set_level((level))
#define SCA_TRACE_LEVEL_NORMAL   SCA_TRACE_LEVEL(LOG_LEVEL_NORMAL)
#define SCA_TRACE_LEVEL_LOW_DBG  SCA_TRACE_LEVEL(LOG_LEVEL_LOW_DBG)
#define SCA_TRACE_LEVEL_DEBUG    SCA_TRACE_LEVEL(LOG_LEVEL_FULL_DEBUG)

#define SCA_TRACE_OUTPUT(output) sca_trace_set_output_type((output))
#define SCA_TRACE_OUTPUT_STD     SCA_TRACE_OUTPUT(LOG_OUTPUT_STD)
#define SCA_TRACE_OUTPUT_FILE    SCA_TRACE_OUTPUT(LOG_OUTPUT_FILE)

#define SCA_TRACE_FILE_PATH(path) sca_trace_set_file_path((path))

#define SCA_TRACE_SHOW_OPT(opt) sca_trace_set_opt((opt))
#define SCA_TRACE_SHOW_DEF \
    SCA_TRACE_SHOW_OPT( \
        LOG_OPT_SHOW_FUNC_LINE | \
        LOG_OPT_SHOW_FILE_PATH | \
        LOG_OPT_FLUSH_EVERYONE | \
        LOG_OPT_FILE_APPEND)

#define SCA_TRACE(info, ...) \
    sca_log_trace(sca_trace_get_log(), info, ##__VA_ARGS__)

#define SCA_TRACE_BIN(name, data, len) \
    sca_trace_trace_bin((name), (data), (len))

#define SCA_TRACE_INFO(info, ...) \
    sca_log_trace_details( \
        sca_trace_get_log(), \
        LOG_TYPE_INFO, \
        __LINE__, \
        __FILE__, \
        __FUNCTION__, \
        (info), ##__VA_ARGS__)

#define SCA_TRACE_WARNING(warning, ...) \
    sca_log_trace_details( \
        sca_trace_get_log(), \
        LOG_TYPE_WARNING, \
        __LINE__, \
        __FILE__, \
        __FUNCTION__, \
        (warning), ##__VA_ARGS__)

#define SCA_TRACE_ERROR(error, ...) \
    sca_log_trace_details( \
        sca_trace_get_log(), \
        LOG_TYPE_ERROR, \
        __LINE__, \
        __FILE__, \
        __FUNCTION__, \
        (error), ##__VA_ARGS__)

#define SCA_TRACE_CODE(code) \
    SCA_TRACE_ERROR( \
        "%s %d-0x%08X %s", \
        sca_err_mod_desc((code)), \
        (code), (code), sca_err_desc((code)))

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_TRACE_H */
