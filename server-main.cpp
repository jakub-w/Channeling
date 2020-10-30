#include <csignal>
#include <iostream>

#include <zmq.hpp>

// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "Server.h"

zmq::context_t ctx;
// auto handshaker = std::make_shared<StupidHandshaker>(ctx, "password");
auto handshaker = std::make_shared<PakeHandshaker>(ctx, "password");
const auto message_handler = [](const Server<PakeHandshaker>::Bytes& data) {
  std::cout.write(reinterpret_cast<const char*>(data.data()),
                  data.size()) << '\n';

  return std::vector<unsigned char>{'r', 'e', 's', 'p', 'o', 'n', 's', 'e'};
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

  server.Bind("ipc://zeromq-server");

  std::cout << "Starting the server...\n";
  server.Run();
}


// FIXME: Other threads don't handle signals so they throw zmq errors on
//        interrupt.
