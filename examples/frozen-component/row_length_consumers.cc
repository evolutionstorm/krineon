#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

namespace {

std::string read_file(const char* path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw std::runtime_error("cannot open input");
  }
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
}

int nibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  throw std::runtime_error("input is not hexadecimal");
}

uint64_t consume_wide(const std::string& input) {
  uint64_t value = 0;
  for (char byte : input) {
    if (byte == '\n' || byte == '\r' || byte == ' ' || byte == '\t') {
      continue;
    }
    const int digit = nibble(byte);
    if (value > (std::numeric_limits<uint64_t>::max() - digit) / 16) {
      throw std::runtime_error("wide consumer overflow");
    }
    value = value * 16 + static_cast<uint64_t>(digit);
  }
  return value;
}

uint32_t consume_narrow(const std::string& input) {
  uint32_t value = 0;
  for (char byte : input) {
    if (byte == '\n' || byte == '\r' || byte == ' ' || byte == '\t') {
      continue;
    }
    value = static_cast<uint32_t>(value * 16U + static_cast<uint32_t>(nibble(byte)));
  }
  return value;
}

void record_coverage(const std::string& mode, bool wrapped) {
  const char* path = std::getenv("KRINEON_COVERAGE_FILE");
  if (path == nullptr || *path == '\0') {
    return;
  }
  std::ofstream stream(path, std::ios::app);
  stream << "entry\nconsumer:" << mode << "\n";
  stream << (wrapped ? "length:wrapped\n" : "length:in-range\n");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: row_length_consumers <wide|narrow> <input>\n";
    return 64;
  }
  try {
    const std::string input = read_file(argv[2]);
    const std::string mode = argv[1];
    const uint64_t wide = consume_wide(input);
    uint64_t observed = 0;
    if (mode == "wide") {
      observed = wide;
    } else if (mode == "narrow") {
      observed = consume_narrow(input);
    } else {
      throw std::runtime_error("unknown consumer");
    }
    const bool wrapped = wide != observed;
    record_coverage(mode, wrapped);
    std::cout << "{\"consumer\":\"" << mode << "\",\"value\":" << observed
              << ",\"wrapped\":" << (wrapped ? "true" : "false") << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 2;
  }
}
