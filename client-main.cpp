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
#include <iostream>
#include <thread>

#include "Client.h"
// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "Util.h"

using namespace Channeling;

int main() {
  auto client = Channeling::MakeClient<PakeHandshaker>("password");

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

  Bytes data{'l', 'a', 'l', 'a', 'l', 'a'};

  const auto print_response = [](const auto& response){
    response.map([](const Bytes& data){
      std::cout << "Response: ";
      std::cout.write(reinterpret_cast<const char*>(data.data()), data.size())
          << '\n';
    }).or_else([](std::error_code ec){
      std::cerr << "Error: " << ec.message() << '\n';
    });
  };

  std::vector<std::future<decltype(client)::MaybeResponse>> responses;
  for (int i = 0; i < 10; ++i) {
    responses.push_back(std::async([&]{ return client.Request(data); }));
    // std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  auto resp = client.Request(Bytes{'f', 'o', 'o'});


  for (auto& response_fut : responses) {
    print_response(response_fut.get());
  }

  return 0;
}
