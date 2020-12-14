#ifndef CHANNELING_LOGGING_H_
#define CHANNELING_LOGGING_H_

#include <spdlog/spdlog.h>

// These wrapper macros are here to ensure that the arguments to logging
// functions aren't being resolved before actually knowing if they will be
// used.

#define LOG_TRACE(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::trace)) { \
    spdlog::trace(__VA_ARGS__);                                         \
  }

#define LOG_DEBUG(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::debug)) { \
    spdlog::debug(__VA_ARGS__);                                         \
  }

#define LOG_INFO(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::info)) { \
    spdlog::info(__VA_ARGS__);                                          \
  }

#define LOG_WARN(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::warn)) { \
    spdlog::warn(__VA_ARGS__);                                          \
  }

#define LOG_ERROR(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::err)) { \
    spdlog::error(__VA_ARGS__);                                         \
  }

#define LOG_CRITICAL(...) \
  if (not (spdlog::default_logger_raw()->level() > spdlog::level::critical)) { \
    spdlog::critical(__VA_ARGS__);                                      \
  }

#endif  // CHANNELING_LOGGING_H_
