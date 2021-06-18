#include "Client.h"

namespace Channeling {

bool ClientBase::Connect(std::string_view address) {
  LOG_INFO("Connecting to {}...", address);

  socket_.connect(address.data());
  // handshaker_->Start();
  handshaker_socket_.connect(handshaker_address_);

  LOG_DEBUG("Requesting ID from server");
  send_to_server(make_msg(MessageType::ID));

  zmq::message_t message;
  if (recv_from_dealer(socket_, message)) { // error code returned
    LOG_ERROR("Received bad ID response");
    LOG_TRACE("Contents: {}", message.str());
    return false;
  }

  std::size_t offset = 0;
  const std::string id = Unpack<std::string>(message.data<char>(),
                                             message.size(),
                                             offset)
                         .value_or("");

  if (id.empty()) {
    LOG_ERROR("Id received from the server was either blank or bunk");
    return false;
  }

  LOG_DEBUG("Sending an initial AUTH request to the server");
  auto auth_request = get_auth_request(id);
  if (not auth_request) {
    return false;
  }

  send_to_server(std::move(auth_request.value()));

  for(;;) {
    if (recv_from_dealer(socket_, message)) { // returned error code
      LOG_ERROR("Bad message received");
      LOG_TRACE("Contents: {}", message.str());
      return false;
    }

    offset = 0;
    const auto type = Unpack<MessageType>(message.data<char>(),
                                          message.size(),
                                          offset)
                      .value_or(MessageType::UNKNOWN);

    LOG_DEBUG("Received {} message from server", MessageTypeName(type));
    LOG_TRACE("Contents: {}", message.str());

    switch (type) {
      case MessageType::AUTH_CONFIRM: {
        auto dec_header = Unpack<crypto::CryptoHeader>(
            message.data<char>(), message.size(), offset);

        if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                 std::holds_alternative<CryptoKey>(encryption_ctx))) {
          LOG_ERROR("Client state inconsistent. Can't proceed with "
                    "encryption setup");
          return false;
        }
        if (not dec_header.has_value()) {
          LOG_ERROR("Decryption header was malformed");
          return false;
        }

        auto dec_key = std::get<CryptoKey>(decryption_ctx);

        decryption_ctx = crypto::SodiumDecryptionContext{};
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

        auto ec = dec_ctx.Initialize(
            dec_key.data(), dec_key.size(),
            dec_header.value().data(), dec_header.value().size());
        if (ec) {
          LOG_ERROR("Protocol error while initializing decryption "
                    "context");
          return false;
        }

        auto enc_key = std::get<CryptoKey>(encryption_ctx);
        encryption_ctx = crypto::SodiumEncryptionContext{};
        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(encryption_ctx);

        crypto::CryptoHeader enc_header;
        ec = enc_ctx.Initialize(enc_key.data(), enc_key.size(),
                                enc_header.data(), enc_header.size());
        if (ec) {
          LOG_ERROR("Protocol error while initializing encryption "
                    "context");
          return false;
        }

        LOG_DEBUG("Sending AUTH_FINISHED message to server");
        send_to_server(make_msg(MessageType::AUTH_FINISHED, enc_header));
        break;
      }
      case MessageType::AUTH_FINISHED: {
        auto dec_header = Unpack<crypto::CryptoHeader>(
            message.data<char>(), message.size(), offset);

        if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                 std::holds_alternative<crypto::SodiumEncryptionContext>(
                     encryption_ctx))) {
          LOG_ERROR("Client state inconsistent. Can't proceed with "
                    "encryption setup");
          return false;
        }
        if (not dec_header.has_value()) {
          LOG_ERROR("Decryption header was malformed");
          return false;
        }

        auto dec_key = std::get<CryptoKey>(decryption_ctx);

        decryption_ctx = crypto::SodiumDecryptionContext{};
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

        auto ec = dec_ctx.Initialize(
            dec_key.data(), dec_key.size(),
            dec_header.value().data(), dec_header.value().size());
        if (ec) {
          LOG_ERROR("Protocol error while initializing decryption "
                    "context");
          return false;
        }

        LOG_INFO("Handshake with {} successfull", address);
        return true;
      }
      case MessageType::ACK: {
        if (not (std::holds_alternative<crypto::SodiumDecryptionContext>(
                decryption_ctx) and
                 std::holds_alternative<crypto::SodiumEncryptionContext>(
                     encryption_ctx))) {
          LOG_ERROR("State inconsistent. Encryption not initialized");
          return false;
        }

        const auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(encryption_ctx);
        const auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

        if (not (enc_ctx.Initialized() and dec_ctx.Initialized())) {
          LOG_ERROR("State inconsistent. Encryption not initialized");
          return false;
        }

        LOG_INFO("Handshake with {} successfull", address);
        return true;
      }
      case MessageType::DENY:
      case MessageType::BAD_MESSAGE:
      case MessageType::PROTOCOL_ERROR:
        LOG_ERROR("Not authenticated. Wrong type message received");
        return false;
      case MessageType::AUTH: {
        zmq::multipart_t msg;
        msg.addstr(id);
        msg.addstr("");
        msg.add(std::move(message));
        msg.send(handshaker_socket_);
        LOG_DEBUG("Forwarding a message to the handshaker");

        msg.recv(handshaker_socket_);

        auto maybe_message = handle_handshaker_message(msg[2]);

        if (not maybe_message) {
          LOG_ERROR("Error while processing a handshaker message");
          return false;
        }

        send_to_server(std::move(maybe_message.value()));
        break;
      }
      default:
        LOG_ERROR("Unhandled message type. Sending BAD_MESSAGE to the "
                  "server");
        send_to_server(make_msg(MessageType::BAD_MESSAGE));
        return false;
    }
  }
}

std::error_code ClientBase::RunAsync() noexcept {
  if (not (
          std::holds_alternative<crypto::SodiumEncryptionContext>(
              encryption_ctx) and
          std::holds_alternative<crypto::SodiumDecryptionContext>(
              decryption_ctx) and
          socket_.connected())) {
    LOG_ERROR("Wrong state to call Run(). "
              "The client isn't properly connected to the server.");
    return std::make_error_code(std::errc::operation_not_permitted);
  }
  try {
    // TODO: This should be initialized in the last stage of Connect().
    //       RequestProcessor should probably take ownership over the
    //       contexts.
    req_processor_ = RequestProcessor{
      socket_,
      &std::get<crypto::SodiumEncryptionContext>(encryption_ctx),
      &std::get<crypto::SodiumDecryptionContext>(decryption_ctx)};

    req_processor_.RunAsync();

    LOG_INFO("Client started");
    return {};
  } catch (const std::exception& e) {
    LOG_ERROR("Error starting the client: {}", e.what());
    return std::make_error_code(std::errc::protocol_error);
  } catch (...) {
    LOG_ERROR("Error starting the client: unknown error");
    return std::make_error_code(std::errc::protocol_error);
  }
}

tl::expected<zmq::message_t, std::error_code>
ClientBase::get_auth_request(const std::string& id) noexcept {
  try {
    zmq::multipart_t message;
    message.addstr(id);
    message.addstr("");
    message.add(make_msg(MessageType::AUTH_REQUEST, id));
    // zmq::message_t message = make_msg(MessageType::AUTH_REQUEST, id);
    message.send(handshaker_socket_);
    // handshaker_socket_.send(std::move(message),
    //                         zmq::send_flags::none);
    // while (not handshaker_socket_.recv(message));
    while (not message.recv(handshaker_socket_));

    auto type = Unpack<MessageType>(message[2].data<char>(), message.size())
                .value_or(MessageType::UNKNOWN);
    if (type != MessageType::AUTH) {
      LOG_ERROR("Couldn't get an initial auth request from the handshaker. "
                "Received message of type: {}", MessageTypeName(type));
      return
          tl::unexpected{std::make_error_code(std::errc::protocol_error)};
    }

    return tl::expected<zmq::message_t, std::error_code>{
      std::move(message[2])};
  } catch (const zmq::error_t& e) {
    LOG_ERROR(
        "ZMQ error while sending GET_AUTH_REQUEST to the handshaker: {}",
        e.what());
    return tl::unexpected{std::make_error_code(std::errc::protocol_error)};
  } catch (const std::exception& e) {
    LOG_ERROR("Error while sending GET_AUTH_REQUEST to the handshaker: {}",
              e.what());
    return tl::unexpected{std::make_error_code(std::errc::protocol_error)};
  } catch (...) {
    LOG_ERROR(
        "Unknown error while sending GET_AUTH_REQUEST to the handshaker");
    return tl::unexpected{std::make_error_code(std::errc::protocol_error)};
  }
}

std::optional<zmq::message_t>
ClientBase::handle_handshaker_message(const zmq::message_t& message) {
  std::size_t offset = 0;
  auto maybe_type = Unpack<HandshakerMessageType>(
      message.data<char>(), message.size(), offset);
  if (not maybe_type) {
    LOG_ERROR("Error determining message type of a message received "
              "from the handshaker");
    return {};
  }

  LOG_DEBUG("Message {} received from the handshaker",
            HandshakerMessageTypeName(maybe_type.value()));

  std::stringstream buffer;

  switch (maybe_type.value()) {
    case HandshakerMessageType::MESSAGE: {
      LOG_DEBUG("Passing handshaker message to the server");

      // TODO: Check if the message from the handshaker is DENY or
      //       BAD_MESSAGE and drop the connection if so.

      buffer.write(message.data<char>() + offset,
                   message.size() - offset);
      offset = message.size(); // just in case

      break;
    }
    case HandshakerMessageType::KEYS: {
      auto maybe_keypair =
          Unpack<EncKeys>(message.data<char>(), message.size(), offset);
      if (not maybe_keypair) {
        LOG_ERROR("Failed to unpack encryption keys received from the "
                  "handshaker");
        msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
        break;
      }

      auto& keypair = maybe_keypair.value();

      const auto& enc_key = keypair.get<0>();
      decryption_ctx = std::move(keypair.get<1>());

      encryption_ctx = crypto::SodiumEncryptionContext{};
      auto& enc_ctx =
          std::get<crypto::SodiumEncryptionContext>(encryption_ctx);

      crypto::CryptoHeader enc_header;
      const auto ec = enc_ctx.Initialize(
          enc_key.data(), enc_key.size(),
          enc_header.data(), enc_header.size());

      if (ec) {
        LOG_ERROR("Error initializing encryption context for client");
        msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
      } else {
        LOG_DEBUG("Sending AUTH_CONFIRM to the server");
        msgpack::pack(buffer, MessageType::AUTH_CONFIRM);
        msgpack::pack(buffer, enc_header);
      }

      break;
    }
    case HandshakerMessageType::KEYS_AND_MESSAGE: {
      auto maybe_keypair =
          Unpack<EncKeys>(message.data<char>(), message.size(), offset);
      if (not maybe_keypair) {
        LOG_ERROR("Failed to unpack encryption keys received from the "
                  "handshaker");
        msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
        break;
      }

      auto& keypair = maybe_keypair.value();

      // We don't need a crypto header yet. We can generate it when we
      // receive AUTH_CONFIRM.

      encryption_ctx = std::move(keypair.get<0>());
      decryption_ctx = std::move(keypair.get<1>());

      LOG_ERROR("Passing handshaker message to the server");
      buffer.write(message.data<char>() + offset,
                   message.size() - offset);
      offset = message.size(); // just in case

      break;
    }
  }

  const auto buffer_str = buffer.str();
  return zmq::message_t{buffer_str.data(), buffer_str.size()};
}
}
