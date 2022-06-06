#ifndef SCA_LOG_API_H
#define SCA_LOG_API_H

#include "sca_type.h"
#include "sca_error.h"

/*===========================================================================*/
/* 日志工具 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 日志输出级别 */
#define LOG_LEVEL_NORMAL        0x00000001U /* 常规级别，仅输出错误信息 */
#define LOG_LEVEL_LOW_DBG       0x00000002U /* 低级调试，输出所有的错误日志和警告信息 */
#define LOG_LEVEL_FULL_DEBUG    0x00000003U /* 可输出所有的日志信息 */

/* 日志输出方式 */
#define LOG_OUTPUT_STD          0x00000010U /* 输出方式-标准输出 */
#define LOG_OUTPUT_FILE         0x00000020U /* 输出方式-文件输出 */

/* 日志类型 */
#define LOG_TYPE_INFO           0x00000001U /* 普通信息 */
#define LOG_TYPE_WARNING        0x00000002U /* 警告信息 */
#define LOG_TYPE_ERROR          0x00000003U /* 错误信息 */

/* 日志工具选项 */
#define LOG_SHOW_DEF_OPT        0x00000000U /* 默认设置 */
#define LOG_SHOW_FUNC_LINE      0x10000000U /* 详细信息显示函数及行号 */
#define LOG_SHOW_FILE_PATH      0x20000000U /* 详细信息显示文件路径 */
#define LOG_FLUSH_EVERYONE      0x01000000U /* 输出时每条日志均刷新 */
#define LOG_FILE_APPEND         0x02000000U /* 开启文件追加模式 */

/* 日志对象 */
typedef void *SCA_LOG;

/* 创建/释放日志工具 */
SCA_UINT32 sca_log_new(SCA_LOG *log, const char *name);
SCA_UINT32 sca_log_free(SCA_LOG log);

/* 创建临时缓冲区(单位：byte，不调用该函数时，默认大小是 1024) */
SCA_UINT32 sca_log_new_buff(SCA_LOG log, SCA_UINT32 len);

/* 设置日志级别 */
SCA_UINT32 sca_log_set_level(SCA_LOG log, SCA_UINT32 level);

/* 设置输出方式 */
SCA_UINT32 sca_log_set_output_type(SCA_LOG log, SCA_UINT32 type);

/* 设置日志选项 */
SCA_UINT32 sca_log_set_opt(SCA_LOG log, SCA_UINT32 opt);

/* 设置日志文件保存路径 */
SCA_UINT32 sca_log_set_file_path(SCA_LOG log, const char *path);

/* 输出未格式化信息 */
SCA_UINT32 sca_log_trace(SCA_LOG log, const char *info, ...);

/* 输出二进制信息 */
SCA_UINT32 sca_log_trace_bin(
    SCA_LOG log,
    const char *name,
    const SCA_UINT8 *data,
    SCA_UINT32 size
);

/*
 * 输出格式化信息
 *
 * 格式化信息的形式为：
 * [name info-typename date]: info-string file:xxx/xxxx/ func:xxxxxx line:
 */
SCA_UINT32 sca_log_trace_details(
    SCA_LOG log,
    SCA_UINT32 type,     /* 日志类型 */    
    SCA_UINT32 line,     /* 行数 */
    const char *file,    /* 所属文件 */
    const char *func,    /* 所属函数 */
    const char *info,    /* 日志信息 */
    ...
);

/* 以下是专门为调用者提供的日志工具快速定义模板 */

/* 本地使用的日志工具 */
#define LOG_TRACE_DECLARE(prefix) \
    SCA_UINT32 prefix##_new(); \
    SCA_UINT32 prefix##_free(); \
    SCA_UINT32 prefix##_new_buff(SCA_UINT32 len); \
    SCA_UINT32 prefix##_set_level(SCA_UINT32 level); \
    SCA_UINT32 prefix##_set_output_type(SCA_UINT32 type); \
    SCA_UINT32 prefix##_set_opt(SCA_UINT32 opt); \
    SCA_UINT32 prefix##_set_file_path(const char *path); \
    SCA_UINT32 prefix##_trace_bin(const char *name, const SCA_UINT8 *data, SCA_UINT32 size); \
    SCA_LOG prefix##_get_log();

/*
 * 本地使用的日志工具，调用者应提供唯一的前缀(prefix)、日志模块名称(name)
 *
 * 举例说明，用户可用宏定义这样的功能:
 * LOG_TRACE_DECLARE(prefix)
 * LOG_TRACE_IMPLEMENT(prefix, name)
 *
 * #define LOG_TRACE_OUTPSCA_FILE(path) \
 *        prefix_set_file_path((path))
 *
 * #define LOG_TRACE(str, ...) \
 *        sca_log_trace(prefix_get_log(), (str), __VA_ARGS__)
 */
#define LOG_TRACE_IMPLEMENT(prefix, mode_name) \
    static SCA_LOG prefix##_handle = NULL; \
    \
    SCA_UINT32 prefix##_new() { \
        return sca_log_new(&prefix##_handle, #mode_name); \
    } \
    SCA_UINT32 prefix##_free() { \
        return sca_log_free(prefix##_handle); \
    } \
    SCA_UINT32 prefix##_new_buff(SCA_UINT32 len) { \
        return sca_log_new_buff(prefix##_handle, len); \
    } \
    SCA_UINT32 prefix##_set_level(SCA_UINT32 level) { \
        return sca_log_set_level(prefix##_handle, level); \
    } \
    SCA_UINT32 prefix##_set_output_type(SCA_UINT32 type) { \
        return sca_log_set_output_type(prefix##_handle, type); \
    } \
    SCA_UINT32 prefix##_set_opt(SCA_UINT32 opt) { \
        return sca_log_set_opt(prefix##_handle, opt); \
    } \
    SCA_UINT32 prefix##_set_file_path(const char *path) { \
        return sca_log_set_file_path(prefix##_handle, path); \
    } \
    SCA_UINT32 prefix##_trace_bin(const char *name, const SCA_UINT8 *data, SCA_UINT32 size) { \
        return sca_log_trace_bin(prefix##_handle, name, data, size); \
    } \
    SCA_LOG prefix##_get_log() { \
        return prefix##_handle; \
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_LOG_API_H */
