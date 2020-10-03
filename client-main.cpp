#include "Client.h"
#include "Handshaker.h"
// #include "PakeHandshaker.h"

int main() {
  zmq::context_t ctx;

  Client client{ctx, std::make_shared<StupidHandshaker>(ctx, "password")};
  // Client client{ctx, std::make_shared<PakeHandshaker>(ctx, "password")};

  if (client.Connect("ipc://zeromq-server")) {
    std::cout << "Connection established successfully!\n";
    return 0;
  }

  std::cerr << "Connection failed\n";
  return 1;
}
