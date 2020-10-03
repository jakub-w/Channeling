#include <csignal>
#include <iostream>

#include <zmq.hpp>

#include "Handshaker.h"
#include "Server.h"

zmq::context_t ctx;
auto handshaker = std::make_shared<StupidHandshaker>(ctx, "password");
Server server(ctx, handshaker);

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
