#ifndef CHANNELING_REQUESTPROCESSOR_H_
#define CHANNELING_REQUESTPROCESSOR_H_

#include <future>
#include <mutex>
#include <utility>

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "Logging.h"
#include "ProtocolCommon.h"
#include "SodiumCipherStream/SodiumCipherStream.h"
#include "Util.h"

namespace Channeling {
class RequestProcessor {
 public:
  using MaybeResponse = tl::expected<Bytes, std::error_code>;

  RequestProcessor(zmq::socket_ref server,
                   crypto::SodiumEncryptionContext* enc_ctx,
                   crypto::SodiumDecryptionContext* dec_ctx)
      : server_{server},
        enc_ctx_{enc_ctx},
        dec_ctx_{dec_ctx} {}

  RequestProcessor(RequestProcessor&& other)
      : server_{std::move(other.server_)},
        enc_ctx_{std::move(other.enc_ctx_)},
        dec_ctx_{std::move(other.dec_ctx_)}
  {
    bool was_running = other.running_;
    if (was_running) {
      other.Stop();
    }
    promises_ = std::move(other.promises_);
    if (was_running) {
      RunAsync();
    }
  }

  const RequestProcessor& operator=(RequestProcessor&& other) {
    server_ = std::move(other.server_);
    enc_ctx_ = std::move(other.enc_ctx_);
    dec_ctx_ = std::move(other.dec_ctx_);
    bool was_running = other.running_;
    if (was_running) {
      other.Stop();
    }
    promises_ = std::move(other.promises_);
    if (was_running) {
      RunAsync();
    }
    return *this;
  }

  RequestProcessor(const RequestProcessor& other) = delete;
  const RequestProcessor& operator=(const RequestProcessor& other) = delete;

  ~RequestProcessor() {
    Stop();
  }

  [[nodiscard]]
  std::future<MaybeResponse>
  MakeRequest(const unsigned char* data, size_t size) {
    decltype(promises_)::iterator it;
    const req_id_t num = ++counter_;
    {
      std::lock_guard lck(promises_mtx_);
      it = promises_.insert_or_assign(num, std::promise<MaybeResponse>{})
           .first;
    }

    const auto make_error = [this, it](std::errc type) {
      it->second.set_value(
          tl::unexpected{std::make_error_code(type)});
      auto future = it->second.get_future();
      std::lock_guard lck{promises_mtx_};
      promises_.erase(it);
      return future;
    };

    if (not running_) {
      return make_error(std::errc::operation_not_permitted);
    }

    crypto::Bytes ciphertext(size + crypto::NA_SS_ABYTES);
    auto ec = enc_ctx_->Encrypt(data, size,
                                ciphertext.data(), ciphertext.size());
    if (ec) {
      // TODO: Handle ec
      LOG_ERROR("Error while encrypting data");
      return make_error(std::errc::protocol_error);
    }

    LOG_DEBUG("Sending ENCRYPTED_DATA message to the server");
    try {
      auto msg = make_msg(MessageType::ENCRYPTED_DATA, num, ciphertext);
      std::lock_guard lck(send_mtx_);
      server_.send(zmq::str_buffer(""), zmq::send_flags::sndmore);
      server_.send(std::move(msg), zmq::send_flags::dontwait);
    } catch (const std::exception& e) {
      LOG_ERROR("Error packing or sending a message: {}", e.what());
      return make_error(std::errc::protocol_error);
    }

    return it->second.get_future();
  }

  inline void Stop() {
    running_ = false;
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  inline void Run() {
    if (running_.exchange(true)) return;
    server_loop();
  }

  inline void RunAsync() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&RequestProcessor::server_loop, this);
  }

 private:
  void server_loop() noexcept {
    zmq::message_t message;

    std::array<zmq::pollitem_t, 1> items {{
        zmq::pollitem_t{server_.handle(), 0, ZMQ_POLLIN, 0}
      }};

    while (running_) {
      try {
        zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));
      } catch (const zmq::error_t& e) {
        if (EINTR != e.num()) {
          LOG_ERROR("Poll error: {}", e.what());
        }
        running_ = false;
        return;
      }

      if (items[0].revents & ZMQ_POLLIN) {
        try {
          if (recv_from_dealer(server_, message)) { // returned an error code
            LOG_ERROR("Received an unexpectedly structured message. "
                      "Discarding.");
            continue;
          }

          std::size_t offset = 0;
          const auto type = Unpack<MessageType>(message.data<char>(),
                                                message.size(), offset)
                            .value_or(MessageType::UNKNOWN);
          const auto request_id = Unpack<req_id_t>(message.data<char>(),
                                                   message.size(), offset)
                                  .value_or(0);
          LOG_DEBUG("Message received. Type: {}, request id: {}",
                    MessageTypeName(type), request_id);
          LOG_TRACE("Contents: {}", to_hex(message.to_string_view()));

          if (0 == request_id) {
            LOG_ERROR("Bad message received, containing not allowed "
                      "request id of 0 (or none at all)");
            continue;
          }

          const auto promise_handle = [this, request_id]() {
            std::lock_guard lck{promises_mtx_};
            return promises_.extract(request_id);
          }();

          if (promise_handle.empty()) {
            LOG_ERROR("Received message has an invalid request id. "
                      "It doesn't match any of the awaiting requests");
            continue;
          }

          auto& promise = promise_handle.mapped();

          if (MessageType::ENCRYPTED_DATA != type) {
            LOG_ERROR("Received message has a wrong type: {}",
                      MessageTypeName(type));
            promise.set_value(make_unexpected(std::errc::protocol_error));
            continue;
          }

          Unpack<Bytes>(message.data<char>(), message.size(), offset)
              .map([this, &promise](crypto::Bytes&& ciphertext){
                const auto maybe_cleartext = dec_ctx_->Decrypt(ciphertext);
                if (std::holds_alternative<std::error_code>(
                        maybe_cleartext)) {
                  LOG_ERROR("Error decrypting received message");
                  promise.set_value(
                      make_unexpected(std::errc::protocol_error));
                  return;
                }

                promise.set_value(std::move(
                    std::get<crypto::Bytes>(maybe_cleartext)));
              })
              .or_else([&promise](std::error_code&& /*ec*/){
                LOG_ERROR("Error unpacking received message");
                promise.set_value(make_unexpected(std::errc::protocol_error));
              });
        } catch (const std::exception& e) {
          LOG_ERROR("Error when handling user data message: {}",
                        e.what());
          running_ = false;
          return;
        } catch (...) {
          LOG_ERROR("Unknown error when handling user data message");
          running_ = false;
          return;
        }
      }
    }
  }

  inline static std::atomic<req_id_t> counter_ = 0;

  zmq::socket_ref server_;
  crypto::SodiumEncryptionContext* enc_ctx_;
  crypto::SodiumDecryptionContext* dec_ctx_;

  std::map<req_id_t, std::promise<MaybeResponse>> promises_;
  std::mutex promises_mtx_;

  std::mutex send_mtx_;

  std::thread thread_;
  std::atomic_bool running_ = false;
};
}

#endif  // CHANNELING_REQUESTPROCESSOR_H_
