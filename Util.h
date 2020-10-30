// Copyright (C) 2020 by Jakub Wojciech

// This file is part of Channeling

// Lelo Remote Music Player is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.

// Lelo Remote Music Player is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Lelo Remote Music Player. If not, see
// <https://www.gnu.org/licenses/>.

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
