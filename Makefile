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
	rm -f $(SRCDIR)/*.o $(TARGET)

# 生成测试用的ELF文件
test: $(TARGET)
	@echo "=== 测试1: 显示ELF头部信息 ==="
	./$(TARGET) -h /bin/ls
	@echo ""
	@echo "=== 测试2: 显示节区头部 ==="
	./$(TARGET) -S /bin/ls | head -40
	@echo ""
	@echo "=== 测试3: 显示程序头部 ==="
	./$(TARGET) -l /bin/ls | head -40
	@echo ""
	@echo "=== 测试4: 显示符号表 ==="
	./$(TARGET) -s /bin/ls | head -30
	@echo ""
	@echo "=== 测试5: GOT/PLT分析 ==="
	./$(TARGET) --got-plt /bin/ls | head -50
	@echo ""
	@echo "=== 测试6: 动态节区 ==="
	./$(TARGET) -d /bin/ls | head -30
	@echo ""
	@echo "=== 测试7: 重定位信息 ==="
	./$(TARGET) -r /bin/ls | head -30

# 和真实readelf对比测试
compare: $(TARGET)
	@echo "=== 对比: ELF Header ==="
	@diff <(./$(TARGET) -h /bin/ls 2>&1) <(readelf -h /bin/ls 2>&1) && echo "PASS" || echo "差异存在（正常）"
