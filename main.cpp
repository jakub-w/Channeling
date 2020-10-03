#include <iostream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "Channel.h"
#include "Server.h"
#include "ProtocolCommon.h"
// #include "PakeHandshaker.h"

zmq::context_t ctx;

// void client_msg_dispatch(const zmq::multipart_t& message,
//                          zmq::socket_t& socket) {
//   if (message.size() == 0) {
//     std::cerr << "Got empty message\n";
//   }
//   if (message[0].size() != sizeof(MessageType)) {
//     std::cerr << "No MessageType!\n";
//   }

//   const MessageType& type = *message[0].data<MessageType>();

//   switch (type) {
//     case MessageType::AUTH_REQUEST: {
//       std::cout << "Asking for authentication...\n";
//       zmq::multipart_t new_msg;

//       new_msg.pushstr("password");
//       new_msg.pushtyp(MessageType::AUTH_STEP1);

//       new_msg.send(socket);
//       std::cout << message << '\n';

//       new_msg.recv(socket);
//       client_msg_dispatch(new_msg, socket);
//       break;
//     }
//     case MessageType::AUTH_CONFIRM: {
//       std::cout << "Authentication confirmed!\n";
//       break;
//     }
//     case MessageType::AUTH_DENY: {
//       std::cout << "Authentication denied!\n";
//       break;
//     }
//     case MessageType::DATA: {
//       std::cout << "Received data: " << message[1] << '\n';
//       break;
//     }
//     default:
//       std::cout << "Client: Unhandled message type: "
//                 << static_cast<int>(type) << '\n';
//       break;
//   }
// }

// void client_worker() {
//   auto client = zmq::socket_t{ctx, ZMQ_REQ};

//   client.connect("inproc://sock");

//   std::string str{"FOO"};
//   // zmq::message_t message{str.c_str(), str.size()};

//   zmq::multipart_t message;
//   message.pushstr(str);
//   message.pushtyp(MessageType::DATA);

//   message.send(client);

//   // client.send(message, zmq::send_flags::dontwait);

//   std::this_thread::sleep_for(std::chrono::milliseconds(20));
//   // std::cout << "Client: " << "recv\n";
//   message.recv(client);
//   // client.recv(message);
//   printf("Client: %s\n", message.str().c_str());

//   client_msg_dispatch(message, client);

//   zmq::multipart_t new_msg;
//   new_msg.pushstr("DATA");
//   new_msg.pushtyp(MessageType::DATA);
//   new_msg.send(client);

//   message.recv(client);

//   client_msg_dispatch(message, client);

//   std::cout << "Client exiting\n";
// }

// struct client_info {
//   bool authenticated = false;
// };


// bool server_verify_client(const std::string& client_id,
//                           client_info& client,
//                           zmq::socket_t& socket) {
//   if (not client.authenticated) {
//     zmq::multipart_t message;
//     message.pushtyp(MessageType::AUTH_REQUEST);
//     message.pushmem("", 0);
//     message.pushmem(client_id.c_str(), client_id.size());
//     message.send(socket);

//     return false;
//   }

//   return true;
// }

// template <typename T>
// std::string to_hex(T container) {
//   std::string result(container.size() * 2, '0');

//   for (size_t i = 0; i < container.size(); ++i) {
//     sprintf(result.data() + i * 2,
//             "%02x",
//             static_cast<unsigned char>(container[i]));
//   }
//   return result;
// }

// void my_test() {
//   auto router = zmq::socket_t{ctx, ZMQ_ROUTER};
//   // zmq::socke

//   router.bind("inproc://sock");

//   std::array<std::thread, 1> threads;
//   for (size_t i = 0; i < threads.size(); ++i) {
//     threads[i] = std::thread(client_worker);
//   }


//   // std::unordered_map<Identity, client_info> clients;
//   std::unordered_map<std::basic_string<char>, client_info> clients;

//   std::array<zmq::pollitem_t, 1> items = {{
//       {static_cast<void*>(router), 0, ZMQ_POLLIN, 0}
//   }};

//   for (;;) {
//     zmq::poll(&items[0], 1, -1);

//     if (items[0].revents & ZMQ_POLLIN) {
//       zmq::multipart_t request(router);

//       const std::string id(
//               static_cast<const char*>(request.front().data()),
//               static_cast<const char*>(request.front().data())
//               + request.front().size());
//       MessageType type = *request[2].data<MessageType>();
//       client_info& client = clients[id];

//       std::cout << "ID: " << request.front() << '\n';
//       std::cout << "Type: " << static_cast<int>(type) << '\n';
//       std::cout << "Authenticated: " << client.authenticated << '\n';
//       std::cout << "Whole: " << request.str() << "\n\n";

//       zmq::multipart_t response;

//       switch (type) {
//         case MessageType::DATA: {
//           if (not server_verify_client(id, client, router)) {
//             continue;
//           }

//           response.pushstr("LALALA");
//           response.pushtyp(MessageType::DATA);
//           response.pushmem("", 0);
//           response.pushstr(id);
//           response.send(router);

//           break;
//         }
//         case MessageType::AUTH_STEP1: {
//           std::cout << "Received auth request\n";
//           if (request.size() != 4) {
//             response.pushtyp(MessageType::AUTH_DENY);
//             response.pushmem("", 0);
//             response.pushstr(id);
//             response.send(router);

//             break;
//           }

//           std::string_view content{
//             request[3].data<char>(), request[3].size()};

//           if (content.compare("password") == 0) {
//             client.authenticated = true;
//             response.pushtyp(MessageType::AUTH_CONFIRM);
//           } else {
//             response.pushtyp(MessageType::AUTH_DENY);
//           }

//           response.pushmem("", 0);
//           response.pushstr(id);

//           std::cout << "Sending response: " << response << '\n';

//           response.send(router);

//           break;
//         }
//         default: {
//           std::cout << "Message type unhandled: "
//                     << static_cast<int>(type) << '\n';

//           break;
//         }
//       }
//     }



//     // std::cout << msg.str() << '\n';

//     // router.send(msg, zmq::send_flags::dontwait);
//   }

//   for (auto& thread : threads) {
//     if (thread.joinable()) thread.join();
//   }
// }


int main() {
  auto handshaker = std::make_shared<StupidHandshaker>(ctx, "password");
  Server server(ctx, handshaker);

  std::thread server_thread(
      [&server]{
        server.Bind("inproc://my-socket");

        server.Run();
      });

  zmq::socket_t socket{ctx, ZMQ_REQ};
  socket.connect("inproc://my-socket");
  std::cout << "ID: "
            << to_hex(socket.getsockopt<std::string>(ZMQ_IDENTITY))
            << '\n';

  std::stringstream ss;
  msgpack::pack(ss, MessageType::AUTH);
  msgpack::pack(ss, "password");

  std::string buf = ss.str();
  socket.send(zmq::const_buffer(buf.data(), buf.size()));

  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  zmq::message_t message;
  socket.recv(message).has_value();
  std::cout << "Response received:\n";
  std::cout << message.str() << '\n';

  auto handle = msgpack::unpack(message.data<char>(), message.size());
  auto object = handle.get();
  auto type = object.as<MessageType>();

  std::cout << "Type: " << MessageTypeName(type) << '\n';

  server.Close();

  server_thread.join();

  return 0;
}
