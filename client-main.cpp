#include <chrono>
#include <thread>

#include "Client.h"
// #include "Handshaker.h"
#include "PakeHandshaker.h"
#include "Util.h"

int main() {
  zmq::context_t ctx;

  // Client client{ctx, std::make_shared<StupidHandshaker>(ctx, "password")};
  Client client{ctx, std::make_shared<PakeHandshaker>(ctx, "password")};

  const auto start = std::chrono::high_resolution_clock::now();
  if (not client.Connect("ipc://zeromq-server")) {
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
