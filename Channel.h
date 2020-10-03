#ifndef CHANNEL_H
#define CHANNEL_H

#include "Handshaker.h"

template <typename T>
class Channel {
 public:
  Channel(std::shared_ptr<Handshaker<T>>&& handshaker)
      : handshaker_{std::move(handshaker)} {}

 private:
  std::shared_ptr<Handshaker<T>> handshaker_;
};

#endif /* CHANNEL_H */
