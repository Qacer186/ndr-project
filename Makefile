# NDR System Makefile
# Modular build system for C++ sensor

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -fPIC -I./include
LDFLAGS = -lpcap

# Directories
SRC_DIR = src
BUILD_DIR = build
TARGET = ndr_sensor

# Source files
SRCS = $(SRC_DIR)/main.cpp $(SRC_DIR)/Detector.cpp $(SRC_DIR)/Emitter.cpp
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
HEADERS = include/Config.hpp include/Detector.hpp include/Emitter.hpp

# Targets
all: $(TARGET)

$(TARGET): $(BUILD_DIR) $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	@echo ""
	@echo "✓ Sensor compiled successfully: $(TARGET)"
	@echo ""

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(HEADERS)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@rm -rf $(BUILD_DIR) $(TARGET)
	@echo "✓ Clean complete"

run: $(TARGET)
	@echo "Running sensor (requires sudo)..."
	sudo ./$(TARGET)

debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

help:
	@echo "NDR Sensor Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make          - Build the sensor"
	@echo "  make run      - Build and run (sudo required)"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make debug    - Build with debug symbols"
	@echo "  make help     - Show this help"

.PHONY: all clean run debug help
