CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I src
TARGET   := myreadelf
SRCDIR   := src
SRCS     := $(wildcard $(SRCDIR)/*.cpp)
OBJS     := $(SRCS:.cpp=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o $(TARGET) /tmp/test_elf /tmp/test_elf.o

# ── 自动测试（覆盖三种ELF格式：可执行文件/共享库/目标文件）──────────
.PHONY: test test-exec test-so test-obj test-ext

# 生成测试用目标文件
/tmp/test_elf.o /tmp/test_elf:
	@printf '#include<cstring>\n#include<cstdio>\ntemplate<typename T>T mymax(T a,T b){return a>b?a:b;}\nint main(){char b[32];memcpy(b,"hi",2);printf("%d\\n",mymax(1,2));return 0;}\n' > /tmp/_test_src.cpp
	g++ -std=c++17 -c /tmp/_test_src.cpp -o /tmp/test_elf.o
	g++ -std=c++17 -fstack-protector -D_FORTIFY_SOURCE=2 /tmp/_test_src.cpp -o /tmp/test_elf
	@rm -f /tmp/_test_src.cpp

EXEC := /bin/ls
SO   := /usr/lib/x86_64-linux-gnu/libc.so.6
OBJ  := /tmp/test_elf.o

# 单条测试辅助：运行命令，检查退出码并打印 PASS/FAIL
define RUN
	@if ./$(TARGET) $(1) > /dev/null 2>&1; then \
		echo "  \033[1;32m[PASS]\033[0m $(1)"; \
	else \
		echo "  \033[1;31m[FAIL]\033[0m $(1)"; exit 1; \
	fi
endef

test: $(TARGET) /tmp/test_elf.o /tmp/test_elf
	@echo ""
	@echo "\033[1m══════════════════════════════════════════════\033[0m"
	@echo "\033[1m  myreadelf 自动测试套件\033[0m"
	@echo "\033[1m══════════════════════════════════════════════\033[0m"
	@echo ""
	@echo "── 第一类：可执行文件 ($(EXEC)) ──────────────────"
	$(call RUN,-h $(EXEC))
	$(call RUN,-l $(EXEC))
	$(call RUN,-S $(EXEC))
	$(call RUN,-t $(EXEC))
	$(call RUN,-s $(EXEC))
	$(call RUN,-r $(EXEC))
	$(call RUN,-d $(EXEC))
	$(call RUN,-n $(EXEC))
	$(call RUN,-V $(EXEC))
	$(call RUN,-I $(EXEC))
	$(call RUN,-A $(EXEC))
	$(call RUN,-x .text $(EXEC))
	$(call RUN,--got-plt $(EXEC))
	$(call RUN,--checksec $(EXEC))
	$(call RUN,--layout $(EXEC))
	$(call RUN,-a $(EXEC))
	@echo ""
	@echo "── 第二类：共享库 ($(notdir $(SO))) ────────────────"
	$(call RUN,-h $(SO))
	$(call RUN,-S $(SO))
	$(call RUN,-s $(SO))
	$(call RUN,-d $(SO))
	$(call RUN,--checksec $(SO))
	$(call RUN,--layout $(SO))
	$(call RUN,--got-plt $(SO))
	@echo ""
	@echo "── 第三类：可重定位目标文件 (.o) ────────────────────"
	$(call RUN,-h $(OBJ))
	$(call RUN,-S $(OBJ))
	$(call RUN,-s $(OBJ))
	$(call RUN,-r $(OBJ))
	$(call RUN,-g $(OBJ))
	$(call RUN,--layout $(OBJ))
	@echo ""
	@echo "\033[1;32m══ 全部测试通过 ══\033[0m"
	@echo ""

# ── 与真实 readelf 对比（检查核心字段一致性）──────────────────────
SHELL := /bin/bash
.PHONY: compare
compare: $(TARGET)
	@echo ""
	@echo "── 与 readelf 核心字段对比 ──────────────────────────"
	@printf "  ELF Header (-h): "; \
	 diff <(./$(TARGET) -h $(EXEC) 2>&1 | grep -E "Class:|Machine:|Entry point") \
	      <(readelf    -h $(EXEC) 2>&1 | grep -E "Class:|Machine:|Entry point") \
	      > /dev/null 2>&1 \
	 && echo -e "\033[1;32mPASS\033[0m" || echo -e "\033[1;31mDIFF\033[0m"
	@printf "  Section count:   "; \
	 diff <(./$(TARGET) -S $(EXEC) 2>&1 | grep "section headers") \
	      <(readelf    -S $(EXEC) 2>&1 | grep "section headers") \
	      > /dev/null 2>&1 \
	 && echo -e "\033[1;32mPASS\033[0m" || echo -e "\033[1;31mDIFF\033[0m"
	@printf "  Symbol count:    "; \
	 diff <(./$(TARGET) -s $(EXEC) 2>&1 | grep "contains") \
	      <(readelf    -s $(EXEC) 2>&1 | grep "contains") \
	      > /dev/null 2>&1 \
	 && echo -e "\033[1;32mPASS\033[0m" || echo -e "\033[1;31mDIFF\033[0m"
	@printf "  Dynamic NEEDED:  "; \
	 diff <(./$(TARGET) -d $(EXEC) 2>&1 | grep "NEEDED") \
	      <(readelf    -d $(EXEC) 2>&1 | grep "NEEDED") \
	      > /dev/null 2>&1 \
	 && echo -e "\033[1;32mPASS\033[0m" || echo -e "\033[1;31mDIFF\033[0m"
	@echo ""
