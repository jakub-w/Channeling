#ifndef UTIL_H
#define UTIL_H

#include <string>

// size in bytes
std::string to_hex(const void* data, size_t size) {
  const unsigned char* data_ = static_cast<const unsigned char*>(data);
  std::string result(size * 2, ' ');
  for (size_t i = 0; i < size; ++i) {
    sprintf(result.data() + i * 2, "%02x", data_[i]);
  }
  return result;
}

template <typename Container>
std::string to_hex(const Container& container) {
  return to_hex(std::data(container),
                std::distance(std::begin(container),
                              std::end(container)));
}

#endif /* UTIL_H */
