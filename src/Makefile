
TARGET := simpleca
INC_PATH := . ../inc ../inc/sca
SRC_PATH := . sca sca_adt sca_cmd sca_err sca_log

# 搜索源文件并获取 .c 文件名列表
SRC_FILES := $(foreach dir,$(SRC_PATH),$(wildcard $(dir)/*.c))

# 将源文件名称替换为 .o 名称
OBJ_FILES := $(patsubst %.c,%.o,$(SRC_FILES))

# 将源文件名称替换为 .d 名称
DEP_FILES := $(patsubst %.c,%.d,$(SRC_FILES))

# 所有包含目录前面 + -I
INC_PATHS = $(addprefix -I, $(INC_PATH))

# 搜索源文件
vpath %.c $(SRC_PATH)

# 搜索头文件
vpath %.h $(INC_PATH)

# 定义模式编译规则
%.o:%.c
	gcc -g -c $< -o $@ -MD -MP $(INC_PATHS) -Wall

# 显式定义目标规则，链接生成最终的可执行程序
$(TARGET): $(OBJ_FILES)
	gcc $^ -o $@ -lcrypto -L/opt/openssl3/lib64 -Wl,-rpath=/opt/openssl3/lib64

# 自动生成依赖，将所有的 .d 文件的内容包含在这里 
# - 则表示 Make 不会在文件不存在的情况下的报错
-include $(DEP_FILES)

.PHONY: clean show
clean:
	rm -f $(DEP_FILES) $(OBJ_FILES) $(TARGET) main.d main.o simpleca

show:
	@echo $(SRC_FILES)
	@echo $(OBJ_FILES)
	@echo $(DEP_FILES)
	@echo $(INC_PATHS)
