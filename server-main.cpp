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

// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "ProtocolCommon.h"
#include "Server.h"

using namespace Channeling;

const auto message_handler = [](Bytes&& data) mutable {
  std::cout.write(reinterpret_cast<const char*>(data.data()),
                  data.size()) << '\n';

  return Bytes{'r', 'e', 's', 'p', 'o', 'n', 's', 'e'};
};

auto server =
    Channeling::MakeServer<PakeHandshaker>(message_handler, "password");

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

  server.Run();
}


// FIXME: Other threads don't handle signals so they throw zmq errors on
//        interrupt.
