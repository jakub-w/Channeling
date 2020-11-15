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

#include <csignal>
#include <iostream>
#include <memory>

#include <zmq.hpp>

// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "ProtocolCommon.h"
#include "Server.h"

auto ctx = std::make_shared<zmq::context_t>();
// auto handshaker = std::make_shared<StupidHandshaker>(ctx, "password");
auto handshaker = std::make_shared<PakeHandshaker>(ctx, "password");
const auto message_handler = [](Bytes&& data) {
  std::cout.write(reinterpret_cast<const char*>(data.data()),
                  data.size()) << '\n';

  return Bytes{'r', 'e', 's', 'p', 'o', 'n', 's', 'e'};
};
Server server(ctx, handshaker, message_handler);

void close_server(int signum) {
  if (signum == SIGTERM or
      signum == SIGINT) {
    server.Close();
  }
}

int main() {
  std::signal(SIGTERM, close_server);
  std::signal(SIGINT, close_server);

  server.Bind("ipc:///tmp/zeromq-server");

  std::cout << "Starting the server...\n";
  server.Run();
}


// FIXME: Other threads don't handle signals so they throw zmq errors on
//        interrupt.
