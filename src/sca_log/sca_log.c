#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include "sca_log.h"
#include "../sca_err/sca_log_err.h"

/*===========================================================================*/

#define LOG_STR_INFO_FLG    "Info"
#define LOG_STR_WARNING_FLG "Warning"
#define LOG_STR_ERROR_FLG   "Error"

#define LOG_LEVEL_MASK      0x0000000FU
#define LOG_OUTPSCA_MASK    0x000000F0U
#define LOG_TYPE_MASK       0x0000FF00U
#define LOG_OPT_MASK        0xFF000000U

#define LOG_CHARSET_NAME_BUFLEN 32   /* 定义字符集名称缓冲区长度 */
#define LOG_NAME_BUFLEN         32   /* 定义日志模块名称缓冲区长度 */
#define LOG_NAME_BUFLEN         32   /* 定义日志模块名称缓冲区长度 */
#define LOG_FORMAT_RESERVE_LEN  64   /* 定义格式化日志信息预留长度 */
#define LOG_FILE_INPSCA_WRITE   "wb" /* 文件模式数据输入模式 */
#define LOG_FILE_INPSCA_APPEND  "ab"

#define LOG_BUFF_SIZE		1024    /* 日志信息缓冲区默认大小(byte)	*/ 
#define LOG_BUFF_MIN_SIZE	512	    /* 日志信息缓冲区最小长度 */ 
#define LOG_BUFF_MAX_SIZE	2048    /* 日志信息缓冲区最大长度 */

/* 日志信息对象 */
struct sca_log_info {
    /* 
     * 0~4   位为日志级别；
     * 4~8   位为日志输出方式；
     * 8~16  位为日志类型；
     * 最高位为是否允许进行字符集编码转换；
     * 剩下的为保留位
     *
     * 原始编码的数据保存在日志缓冲区低地址处 ，如果需要
     * 进行编码转换，转码后的数据保存在缓冲区高地址处，具体的
     * 缓冲区大小根据权重来进行计算。
     *
     * 权重 weight 的低四位代表本地编码日志缓冲区长度权重，高四位代表
     * 编码转换缓冲区长度的权重。
     */
    SCA_UINT32      len;                            /* 日志结构长度 */
    SCA_UINT32      flag;                           /* 日志类型参数 */
    char            log_name[LOG_NAME_BUFLEN];      /* 日志模块名称 */
    FILE            *log_file;                      /* 文件指针 */
    SCA_UINT8       buf_weight;                     /* 日志缓冲区权重 */
    struct sca_data path_buf;                       /* 日志文件路径 */
    struct sca_data log_buf;                        /* 日志缓冲区 */
};

/* 日志输出 */
static SCA_UINT32 log_output(struct sca_log_info *log);

/* 标准输出 */
static SCA_UINT32 log_output_std(struct sca_log_info *log);

/* 文件输出 */
static SCA_UINT32 log_output_file(struct sca_log_info *log);

/* 打开文件 */
static FILE *log_open_file(struct sca_log_info *log, const char *path);

/* 获取本地时间 */
static SCA_UINT32 log_get_curtime(const char *format, char *buf, int len);

SCA_UINT32 sca_log_new(SCA_LOG *log, const char *name)
{
    struct sca_log_info *lgst = NULL;
    SCA_UINT32 flag = 0;
    SCA_UINT32 ret = SCA_ERR_SUCCESS;

    if (!log || !name || !name[0]) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = malloc(sizeof(*lgst));
    if (!lgst) {
        return SCA_ERR_NULL_POINTER;
    }
    memset(lgst, 0, sizeof(*lgst));

    /* 设置长度，用于校验 */
    lgst->len = sizeof(*lgst);

    /* 设置默认的输出级别、输出类型、等属性 */
    flag  = LOG_LEVEL_NORMAL;
    flag |= LOG_OUTPUT_STD;
    flag |= LOG_LEVEL_FULL_DEBUG;

    lgst->flag = flag;
    strncpy(lgst->log_name, name, LOG_NAME_BUFLEN);
    lgst->log_name[LOG_NAME_BUFLEN - 1] = '\0';

    /* 首先设置两个缓冲区长度的权重，然后申请内存 */
    lgst->log_buf.value = (SCA_UINT8 *)malloc(LOG_BUFF_SIZE);
    lgst->log_buf.size = LOG_BUFF_SIZE;

    if (!lgst->log_buf.value) {
        ret = SCA_ERR_NULL_POINTER;
        goto err;
    }

    memset(lgst->log_buf.value, 0, LOG_BUFF_SIZE);
    *log = (SCA_LOG)lgst;

    return SCA_ERR_SUCCESS;

err:
    free(lgst);
    return ret;
}

SCA_UINT32 sca_log_free(SCA_LOG log)
{
    struct sca_log_info *lgst = NULL;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = log;

    if (lgst->len != (SCA_UINT32)sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    /* 释放文件路径缓冲区 */
    if (lgst->path_buf.value) {
        free(lgst->path_buf.value);
        lgst->path_buf.value = NULL;
        lgst->path_buf.size = 0;
    }

    /* 释放缓冲区 */
    if (lgst->log_buf.value) {
        free(lgst->log_buf.value);
        lgst->log_buf.value = NULL;
        lgst->log_buf.size = 0;
    }

    /* 释放文件指针 */
    if (lgst->log_file) {
        fflush(lgst->log_file);
        fclose(lgst->log_file);
        lgst->log_file = NULL;
    }

    free(lgst);
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_new_buff(SCA_LOG log, SCA_UINT32 len)
{
    struct sca_log_info *lgst = NULL;
    SCA_UINT8 *tmp = NULL;
    SCA_UINT32 buf_len = 0;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    if (len < LOG_BUFF_MIN_SIZE || len > LOG_BUFF_MAX_SIZE) {
        return SCA_ERR_PARAM;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    if (!lgst->log_buf.value) {
        tmp = malloc(len * sizeof(SCA_UINT8));
        if (!tmp) {
            return SCA_ERR_NULL_POINTER;
        }

        lgst->log_buf.value = tmp;
        lgst->log_buf.size = len;
    } else if ((buf_len = lgst->log_buf.size) < len) {
        tmp = (SCA_UINT8 *)realloc(lgst->log_buf.value, len);
        if (!tmp) {
            return SCA_ERR_NULL_POINTER;
        }

        /* 定义新增部分 */
        memset(tmp + buf_len, 0, len - buf_len);

        lgst->log_buf.value = tmp;
        lgst->log_buf.size = len;
    } else {
        /* 不需要重新分配内存，只需要调整‘大小’即可 */
        lgst->log_buf.size = len;
    }

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_set_level(SCA_LOG log, SCA_UINT32 level)
{
    struct sca_log_info *lgst = NULL;

    if (!log || !level) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    lgst->flag = (lgst->flag & (~LOG_LEVEL_MASK)) | level;
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_set_output_type(SCA_LOG log, SCA_UINT32 type)
{
    struct sca_log_info *lgst = NULL;

    if (!log || !type) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = (struct sca_log_info *)log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    lgst->flag = (lgst->flag & (~LOG_OUTPSCA_MASK)) | type;
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_set_opt(SCA_LOG log, SCA_UINT32 opt)
{
    struct sca_log_info *lgst = NULL;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    lgst->flag = (opt != LOG_SHOW_DEF_OPT) ? 
        (lgst->flag | (opt & LOG_OPT_MASK)) : (lgst->flag & (~LOG_OPT_MASK));
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_set_file_path(SCA_LOG log, const char *path)
{
    struct sca_log_info *lgst = NULL;
    SCA_UINT32 plen = 0;
    SCA_UINT8 *tmp = NULL;
    FILE *pfile = NULL;

    if (!log || !path || !path[0]) {
        return SCA_ERR_NULL_PARAM;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    tmp = lgst->path_buf.value;
    plen = (SCA_UINT32)strlen(path) + 1;

    if (!tmp) {
        tmp = (SCA_UINT8 *)malloc(plen * sizeof(SCA_UINT8));
        if (!tmp) {
            return SCA_ERR_NULL_POINTER;
        }

        lgst->path_buf.value = tmp;
        lgst->path_buf.size = plen;
    } else if (lgst->path_buf.size < plen) {
        tmp = (SCA_UINT8 *)realloc(lgst->path_buf.value, plen);
        if (!tmp) {
            return SCA_ERR_NULL_POINTER;
        }

        lgst->path_buf.value = tmp;
        lgst->path_buf.size = plen;
    }

    if (lgst->log_file) {
        fflush(lgst->log_file);
        fclose(lgst->log_file);
    }

    /* 打开文件 */
    pfile = log_open_file(lgst, path);
    if (!pfile) {
        return SCA_ERR_LOG_OPEN_FILE;
    }

    strcpy((char *)tmp, path);
    lgst->log_file = pfile;

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_log_trace(SCA_LOG log, const char *info, ...)
{
    int num = 0;
    struct sca_log_info *lgst = NULL;
    va_list arg_list;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!info || !info[0]) {
        return SCA_ERR_NULL_STRING;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    va_start(arg_list, info);
    num = vsnprintf((char *)lgst->log_buf.value, lgst->log_buf.size, info, arg_list);
    va_end(arg_list);

    if (num < 0) {
        return SCA_ERR_LOG_FORMAT;
    }

    return log_output(lgst);
}

SCA_UINT32 sca_log_trace_bin(
    SCA_LOG log, 
    const char *name, 
    const SCA_UINT8 *data, 
    SCA_UINT32 size
)
{
    struct sca_log_info *lgst = NULL;
    SCA_UINT8 *bptr = NULL;
    SCA_UINT32 blen = 0;
    SCA_UINT32 ret  = SCA_ERR_SUCCESS;

    char tmp[4] = { 0 };
    const char *sline = NULL;
    size_t llen = 0;
    size_t offset = 0;
    size_t nlen = 0;

    int i = 0;
    int j = 0;

    if (!log || !data) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!size) {
        return SCA_ERR_PARAM;
    }

    lgst =log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    /* 打印二进制数据，先将数据放入缓冲区，待缓冲区填满再输出 */
    sline = "------------------------+------------------------\n";
    llen = strlen(sline);

    bptr = lgst->log_buf.value;
    blen = lgst->log_buf.size - LOG_FORMAT_RESERVE_LEN;

    if (!name || !*name) {
        name = "BinInfo";
    }

    nlen = strlen(name);

    if (nlen > (size_t)blen) {
        nlen = blen;
    }

    strncpy((char *)bptr, name, blen);
    bptr[blen - 1] = '\0';

    ret = log_output(lgst);
    if (ret != SCA_ERR_SUCCESS) {
        return ret;
    }

    sprintf((char *)bptr, "(%d bytes):\n%s", size, sline);

    offset += strlen((const char *)bptr);
    j = 0;
    i = 0;

    while (i < size) {
        if (i > 0) {
            if (i % 16 == 0) {
                strcat((char *)bptr, "\n");
                offset += 1;
                if (++j % 8 == 0) {
                    strcat((char *)bptr, sline);
                    offset += llen;
                }
            } else if (i % 8 == 0) {
                strcat((char *)bptr, "| ");
                offset += 2;
            }
        }

        if ((i + 1) % 16 == 0) {
            sprintf(tmp, "%02x", data[i]);
            offset += 2;
        } else {
            sprintf(tmp, "%02x ", data[i]);
            offset += 3;
        }

        strcat((char *)bptr, tmp);

        /* 这里预留 64 字节的安全距离 */
        if (offset >= blen) {
            ret = log_output(lgst);
            if (ret != SCA_ERR_SUCCESS) {
                return ret;
            }
            offset = 0;

            /* 清空缓冲区 */
            memset(bptr, 0, lgst->log_buf.size);
        }

        i++;
    }

    strcat((char *)bptr, "\n");
    strcat((char *)bptr, sline);

    ret = log_output(lgst);
    return ret;
}

SCA_UINT32 sca_log_trace_details(
    SCA_LOG log,
    SCA_UINT32 type,  /* 日志类型 */    
    SCA_UINT32 line,  /* 行数 */
    const char *file, /* 所属文件 */
    const char *func, /* 所属函数 */
    const char *info, /* 日志信息 */
    ...
)
{
    int num = 0;
    struct sca_log_info *lgst = NULL;
    SCA_UINT32 ret = SCA_ERR_SUCCESS;
    SCA_UINT32 level = 0;
    SCA_UINT32 offset = 0;

    char buf[64] = { 0 };
    SCA_UINT8 *pbuf = NULL;
    SCA_UINT8 *tmp = NULL;
    size_t tmplen = 0;
    size_t infolen = 0;
    va_list arg_list;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!info || !info[0] ||
        !file || !file[0] ||
        !func || !func[0]) {
        return SCA_ERR_NULL_STRING;
    }

    lgst = log;

    if (lgst->len != sizeof(*lgst)) {
        return SCA_ERR_PARAM;
    }

    level = lgst->flag & LOG_LEVEL_MASK;

    /* 日志等级限制 */
    if (level == LOG_LEVEL_NORMAL) {
        if (type == LOG_TYPE_INFO || type == LOG_TYPE_WARNING) {
            return SCA_ERR_SUCCESS;
        }
    } else if (level == LOG_LEVEL_LOW_DBG) {
        if (type == LOG_TYPE_INFO) {
            return SCA_ERR_SUCCESS;
        }
    } else if (level != LOG_LEVEL_FULL_DEBUG) {
        return SCA_ERR_LOG_TYPE;
    }

    /* 分别取出缓冲区和编码缓冲区长度的权重计算偏移值 */
    offset = lgst->log_buf.size * (lgst->buf_weight & 0x0F) / 
            ((lgst->buf_weight & 0x0F) + (lgst->buf_weight >> 4));

    tmp = lgst->log_buf.value + offset;
    tmplen = lgst->log_buf.size - offset;

    /* 先将带有可变参数字符串的值暂时放在编码缓冲区中 */
    va_start(arg_list, info);
    num = vsnprintf((char *)tmp, tmplen, info, arg_list);
    va_end(arg_list);

    /* 
     * 估算日志信息长度，末尾剩余的 LOG_FORMAT_RESERVE_LEN 字节是
     * 为其他的格式化信息预留的缓冲大小
     */
    infolen = num + strlen(file) + strlen(func) + LOG_FORMAT_RESERVE_LEN;

    pbuf = lgst->log_buf.value;
    if (tmplen < infolen) {
        return SCA_ERR_LOG_BUFFER;
    }

    /* 构建输出信息 */
    strcpy((char *)pbuf, "[");

    if (lgst->log_name[0]) {
        strcat((char *)pbuf, lgst->log_name);
        strcat((char *)pbuf, " ");
    }

    switch (type) {
    case LOG_TYPE_ERROR:
        strcat((char *)pbuf, LOG_STR_ERROR_FLG);
        break;

    case LOG_TYPE_WARNING:
        strcat((char *)pbuf, LOG_STR_WARNING_FLG);
        break;

    case LOG_TYPE_INFO:
    default:
        strcat((char *)pbuf, LOG_STR_INFO_FLG);
    }

    log_get_curtime(" %Y-%m-%d %H:%M:%S]:", buf, sizeof(buf));

    strcat((char *)pbuf, buf);
    strcat((char *)pbuf, (const char *)tmp);

    if (lgst->flag & LOG_SHOW_FILE_PATH) {
        strcat((char *)pbuf, " file:");
        strcat((char *)pbuf, file);
    }

    if (lgst->flag & LOG_SHOW_FUNC_LINE) {
        strcat((char *)pbuf, " func:");
        strcat((char *)pbuf, func);
        strcat((char *)pbuf, " line:");
        sprintf(buf, "%d ", line);
        strcat((char *)pbuf, buf);
    }

    strcat((char *)pbuf, "\n");
    ret = log_output(lgst);

    return ret;
}

/* ========================================================================= */

SCA_UINT32 log_output(struct sca_log_info *log)
{
    SCA_UINT32 ret = SCA_ERR_SUCCESS;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    switch (log->flag & LOG_OUTPSCA_MASK) {
    case LOG_OUTPUT_FILE:
        ret = log_output_file(log);
        break;

    case LOG_OUTPUT_STD:
    default:
        ret = log_output_std(log);
    }

    return ret;
}

/* 标准输出 */
SCA_UINT32 log_output_std(struct sca_log_info *log)
{
    SCA_UINT32 ret = SCA_ERR_SUCCESS;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    /* 进行字符串编码转换 */
    printf("%s", (const char *)log->log_buf.value);

    if (log->flag & LOG_FLUSH_EVERYONE) {
        fflush(stdout);
    }

    return ret;
}

/* 文件输出 */
SCA_UINT32 log_output_file(struct sca_log_info *log)
{
    SCA_UINT32 ret = SCA_ERR_SUCCESS;
    const char *str = NULL;
    FILE **fptr = &log->log_file;

    if (!log) {
        return SCA_ERR_NULL_PARAM;
    }

    if (!(*fptr)) {
        if (!log->path_buf.value || !log->path_buf.value[0]) {
            return SCA_ERR_NULL_STRING;
        }

        /* 打开文件 */
        *fptr = log_open_file(log, (const char *)log->path_buf.value);

        if (!(*fptr)) {
            return SCA_ERR_LOG_OPEN_FILE;
        }
    }

    str = (const char *)log->log_buf.value;
    fwrite((const char *)str, sizeof(const char), strlen(str), *fptr);

    if (log->flag & LOG_FLUSH_EVERYONE)
    {
        fflush(*fptr);
    }

    return ret;
}

FILE *log_open_file(struct sca_log_info *log, const char *path)
{
    FILE *file = NULL;

    if (!log) {
        return NULL;
    }

    if (!path || !*path) {
        return NULL;
    }

    /* 判断是否文件是否属于追加模式 */
    if ((log->flag & LOG_FILE_APPEND) == LOG_FILE_APPEND) {
        file = fopen(path, LOG_FILE_INPSCA_APPEND);
    } else {
        file = fopen(path, LOG_FILE_INPSCA_WRITE);
    }

    return file;
}

SCA_UINT32 log_get_curtime(const char *format, char *buf, int len)
{
	time_t lc_time = 0;
	size_t ret = 0;
	struct tm *lctm = NULL;

	if (!format || !format[0]) {
		return SCA_ERR_NULL_STRING;
	}

	if (!buf) {
		return SCA_ERR_NULL_PARAM;
	}

	if (len <= 0) {
		return SCA_ERR_PARAM;
	}

	memset(buf, 0, len);

	/* 获取本地时间 */
	lc_time = time(NULL);
	lctm = localtime(&lc_time);

	if (!lctm) {
		return SCA_ERR_NULL_POINTER;
	}

	/* 转换时间信息为字符串 */
	ret = strftime(buf, len, format, lctm);
	return !ret ? SCA_ERR_FAILED : SCA_ERR_SUCCESS;
}

/*===========================================================================*/
