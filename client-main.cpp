#include <thread>

#include "Client.h"
// #include "Handshaker.h"
#include "PakeHandshaker.h"

int main() {
  zmq::context_t ctx;

  // Client client{ctx, std::make_shared<StupidHandshaker>(ctx, "password")};
  Client client{ctx, std::make_shared<PakeHandshaker>(ctx, "password")};

  if (not client.Connect("ipc://zeromq-server")) {
    std::cerr << "Connection failed\n";
    return 1;
  }

  std::cout << "Connection established successfully!\n";

  auto thread = std::thread{[&client]{
    client.Run();
  }};

  std::vector<unsigned char> data{'l', 'a', 'l', 'a', 'l', 'a'};
  data = client.Request(data);

  data = client.Request(data);

  client.Stop();
  if (thread.joinable()) {
    thread.join();
  }

  return 0;
}
