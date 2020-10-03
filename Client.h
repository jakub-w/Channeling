#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "ProtocolCommon.h"
#include "Util.h"

// TODO: Implement real client

template <typename Handshaker>
class Client {
 public:
  Client(zmq::context_t& context, std::shared_ptr<Handshaker> handshaker)
      : socket_{context, ZMQ_REQ},
        handshaker_socket_{context, ZMQ_PAIR},
        crypto_handshaker_socket_{context, ZMQ_PAIR},
        handshaker_{std::move(handshaker)} {}

  [[nodiscard]]
  bool Connect(std::string_view address) {
    socket_.connect(address.data());
    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());
    crypto_handshaker_socket_.connect(handshaker_->GetCryptoAddress());

    std::string id(255, ' ');
    size_t id_len = 0;
    socket_.getsockopt(ZMQ_ROUTING_ID, id.data(), &id_len);
    id.resize(id_len);

    socket_.send(handshaker_->GetAuthRequest(id), zmq::send_flags::dontwait);

    for(;;) {
      zmq::message_t message;
      // NOTE: If it doesn't have a value, it means the error EAGAIN was
      //       received.
      if (not socket_.recv(message).has_value()) continue;

      size_t offset = 0;
      const auto type = Unpack<MessageType>(message.data<char>(),
                                            message.size(),
                                            offset)
                        .value_or(MessageType::UNKNOWN);

      switch (type) {
        case MessageType::AUTH_CONFIRM:
          return true;
        case MessageType::DENY: case MessageType::BAD_MESSAGE:
          std::cerr << "Not authenticated. Message received:\n"
                    << "Type: " << MessageTypeName(type) << '\n'
                    << "Data: " << to_hex(message.data<char>() + offset,
                                          message.size() - offset) << '\n';
          return false;
        case MessageType::AUTH:
          handshaker_socket_.send(message, zmq::send_flags::none);
          std::cout << "Forwarded to the handshaker\n\n";
          break;
        default:
          std::cerr << "Unhandled message type: "
                    << MessageTypeName(type) << "\n\n";
          const auto bad_msg = MessageType::BAD_MESSAGE;
          message.rebuild(&bad_msg, sizeof(bad_msg));
          socket_.send(message, zmq::send_flags::dontwait);
          return false;
      }
    }
  }

 private:
  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;
  zmq::socket_t crypto_handshaker_socket_;

  std::shared_ptr<Handshaker> handshaker_;
};

#endif /* CLIENT_H */


// NOTES:
// Make a Server class that will be the hub for all connections.
// It will have a ROUTER socket and will redirect all calls to either the
// Handshaker (when the client isn't yet authenticated) or Channel that is
// assigned to the client. It will also filter all unauthenticated requests
// other than authentication request itself.
// The server will keep a map storing client data.
// Client data being its id, authentication status and a Channel object.
// The Channel and the Handhshaker will talk to the server by ipc sockets.
// This will let them work asynchronously.
//
// Handshaker class that will be passed to the Server in a constructor. It's
// only objective will be exchanging authentication type data with the Server.
// When unauthenticated client sends an authentication request, it will be
// passed to the Handshaker.
// The Handshaker will need the client's id to track its authentication
// status, so the server won't strip it. Or maybe it will send it already
// parsed with msgpack.
// It seems like the Handshaker will need to be stateful and track all pending
// authentication processes and forget them after the authentication is
// completed. The completion message will contain encryption and decryption
// keys that the Server will pass to the Channel.
//
// A new Channel object will be assigned to every client that successfully
// authenticates with the Handshaker.
// The Server will pass all messages to it so it can decrypt and encrypt them.
// It will return either ciphertext that will be sent back to the client or
// plaintext that will be parsed by the Server.
// Maybe I should rename it to something like Decryptor or CryptoStream,
// because in this design the messages don't pass through it. It just encrypts
// and decrypts stuff. Maybe it shouldn't even be connected to the server with
// a socket and just be called directly?

// My first thought was for the Channel to be the client-facing object. It
// would send already decrypted messages to the Server or authentication
// requests to the Handshaker.
// But it's not much of a channel if it's a router facing all the clients at
// once. Is it?
// Which design is more fool-proof? Probably this one.
// The Channel would be a hub and the Server would deal only with unencrypted
// and authenticated messages.
// So the Channel would be a thing that sits between the outside world and the
// application. It would handle encryption and decryption and be a dispatch
// for authentication/handshaking requests and normal, encrypted traffic
// routed to the Server.

// Making a handshaker for every Channel is a waste. It should probably
// take a reference or a pointer to one.


// Maybe a Client and a Server should just contain Handhshakers, Encryptors
// and Decryptors.
// They'd have a ZMQ_ROUTER socket for exchanging info with clients and use
// these three classes to establish connections and crypto stuff.
// The rest would be either done in the poll loop or offloaded to some worker.


// Encryptor and Decryptor won't be a thing. All servers and clients will use
// the same encryption scheme. Handshakers will be replacable.
