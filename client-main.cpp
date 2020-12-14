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

#include <chrono>
#include <thread>

#include "Client.h"
// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "Util.h"

int main() {
  // Client client{ctx, std::make_shared<StupidHandshaker>(ctx, "password")};
  Client client{std::make_shared<PakeHandshaker>("password")};

  const auto start = std::chrono::high_resolution_clock::now();
  if (not client.Connect("ipc:///tmp/zeromq-server")) {
    std::cerr << "Connection failed\n";
    return 1;
  }
  const auto end = std::chrono::high_resolution_clock::now();
  std::cout << "Handshake took "
            << (end - start).count() / 1000000.0
            << "ms\n";

  std::cout << "Connection established successfully!\n";

  auto ec = client.Start();
  if (ec) {
    std::cerr << ec.message() << '\n';
    return 1;
  }

  Bytes data{'l', 'a', 'l', 'a', 'l', 'a'};

  const auto print_response = [](const auto& response){
    response.map([](const Bytes& data){
      std::cout.write(reinterpret_cast<const char*>(data.data()), data.size())
          << '\n';
    }).or_else([](std::error_code ec){
      std::cerr << "Error: " << ec.message() << '\n';
    });
  };
  print_response(client.Request(data));
  print_response(client.Request(data));

  return 0;
}
