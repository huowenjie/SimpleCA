#ifndef SCA_CMD_BUF_H
#define SCA_CMD_BUF_H

#include <sca_type.h>

/*===========================================================================*/
/* 内置缓冲区 */
/*===========================================================================*/

/* 输入输出缓冲区名称 */
#define SCA_BUF_NAME_IO "BUF_IO"

/* 
 * 内置缓冲区的每一次写入都会覆盖原有缓冲区的内容，缓冲区专门用于存放各
 * 种临时运算结果
 */

/* 缓冲区数据类型 */
enum buf_data_type
{
    BINARY = 0,
    STRING
};

/* 创建全局缓冲区 */
int sca_cmd_buf_start();

/* 释放全局缓冲区 */
int sca_cmd_buf_end();

/* 创建缓冲区 */
int sca_cmd_buf_create(const char *name, int size);

/* 销毁内置缓冲区 */
int sca_cmd_buf_destroy(const char *name);

/* 获取当前缓冲区的大小 */
int sca_cmd_buf_size(const char *name);

/* 获取上一次写入的数据大小 */
int sca_cmd_buf_last_size(const char *name);

/* 获取数据类型 */
int sca_cmd_buf_get_type(const char *name);

/* 设置缓冲区数据类型 */
void sca_cmd_buf_set_type(const char *name, int type);

/* 读缓冲区 */
int sca_cmd_buf_read(const char *name, struct sca_data *data);

/* 写入缓冲区，缓冲区不足则自动扩容 */
int sca_cmd_buf_write(const char *name, const struct sca_data *data);

/* 从标准输入读数据到缓冲区 */
int sca_cmd_buf_in_std(const char *name);

/* 从文件中读数据到缓冲区 */
int sca_cmd_buf_in_file(const char *name, const char *file);

/* 将缓冲区数据写入到标准输出 */
int sca_cmd_buf_out_std(const char *name);

/* 将缓冲区数据写入到文件 */
int sca_cmd_buf_out_file(const char *name, const char *file);

/*===========================================================================*/

#endif /* SCA_CMD_BUF_H */
