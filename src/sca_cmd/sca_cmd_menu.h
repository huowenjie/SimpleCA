#ifndef __CMD_MENU_H__
#define __CMD_MENU_H__

/*===========================================================================*/
/* 菜单工具 */
/*===========================================================================*/

#define SELECT_MENU(menu) \
    select_menu((menu), sizeof((menu)) / sizeof((menu)[0]), 0)

#define INPUT_INT(hint) input_int((hint), 0)
#define INPUT_STR(hint) input_str((hint), "")

/* 从标准输入字符串 */
const char *input_str(const char *hint, const char *def);

/* 从标准输入整数 */
int input_int(const char *hint, int def);

/* 显示菜单 */
void show_menu(const char * const * menu, int count);

/* 选择菜单 */
int select_menu(const char * const * menu, int count, int def);

/*===========================================================================*/

#endif /* __CMD_MENU_H__ */
