# 변수 설정
CXX = g++
CXXFLAGS = -Wall -g
DEBUGFLAGS = -DDEBUG
LIBS = -lpcap -lgtest -lgtest_main
TARGET = deauth-attack
SRC = main.cpp

# 기본 타겟 설정
all: $(TARGET)

# 컴파일 규칙
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)
# debug 타겟
debug: $(SRC)
	$(CXX) $(CXXFLAGS) $(DEBUGFLAGS) $^ -o $(TARGET) $(LIBS)
# clean 타겟
clean:
	rm -f $(TARGET)