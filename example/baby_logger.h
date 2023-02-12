#pragma once

#ifndef _LOGGER_H
#define _LOGGER_H

#include <array>
#include <assert.h>
#include <chrono>
#include <fstream>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <iostream>

/*
 *  make_unique is supported in c++14 onwards
 *  Add suport for make_unique in c++ below 14
 */
#if __cplusplus < 201402L
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args &&...args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#endif

#ifdef __ANDROID__
#include <android/log.h>
#endif

// Internal implementation detail
#define LOGGER_LOG__(level)                               \
    ::logger::LogManager::Instance().IsRelevant(level) && \
        ::logger::Log(level).Line()

#define LOG(level) LOGGER_LOG__(level)

#ifndef LOGGER_THREAD_NAME
#if defined(LOGGER_USE_THREAD_NAME)
#include <pthread.h>
inline const char *logger_get_thread_name_() noexcept
{
    thread_local std::array<char, 16> buffer = {};
    if (pthread_getname_np(pthread_self(), buffer.data(), buffer.size()) == 0)
    {
        return buffer.data();
    }
    return "err pthread_getname_np";
}
#define LOGGER_THREAD_NAME logger_get_thread_name_()
#
#elif defined(LOGGER_USE_TID_AS_NAME)
#include <unistd.h>
#include <sys/syscall.h>
#define LOGGER_THREAD_NAME syscall(__NR_gettid)
#else
#define LOGGER_THREAD_NAME std::this_thread::get_id()
#endif
#endif

namespace logger
{

    enum class LogLevel
    {
        DISABLED,
        ERROR,
        WARN,
        NOTICE,
        INFO,
        DEBUG,
        TRACE
    };

#define ERROR logger::LogLevel::ERROR
#define WARN logger::LogLevel::WARN
#define NOTICE logger::LogLevel::NOTICE
#define INFO logger::LogLevel::INFO
#define DEBUG logger::LogLevel::DEBUG
#define TRACE logger::LogLevel::TRACE

    struct Message
    {
        Message(const std::string &&msg, const LogLevel level)
            : msg_{std::move(msg)}, level_{level} {}

        const std::string msg_;
        const std::chrono::system_clock::time_point when_ = std::chrono::system_clock::now();
        const LogLevel level_;
    };

    class Handler
    {
    public:
        Handler(LogLevel level = INFO) : level_{level} {}
        virtual ~Handler() = default;
        using ptr_t = std::unique_ptr<Handler>;

        virtual void LogMessage(const Message &msg) = 0;
        const LogLevel level_;

        static const std::string &LevelName(const LogLevel level)
        {
            static const std::array<std::string, 7> names =
                {{"DISABLED", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"}};
            return names.at(static_cast<size_t>(level));
        }
    };

#ifdef __ANDROID__
    class AndroidHandler : public Handler
    {
    public:
        AndroidHandler(const std::string &name, LogLevel level)
            : Handler(level), name_{name} {}

        void LogMessage(const logger::Message &msg) override
        {
            static const std::array<int, 6> android_priority =
                {ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO,
                 ANDROID_LOG_INFO, ANDROID_LOG_DEBUG, ANDROID_LOG_VERBOSE};
            __android_log_write(android_priority.at(static_cast<int>(level_)),
                                name_.c_str(), msg.msg_.c_str());
        }

    private:
        const std::string name_;
    };
#else

#ifndef LOGGER_USE_UTCZONE
#define LOGGER_USE_UTCZONE 0
#endif

#ifndef LOGGER_TIME_FORMAT
#define LOGGER_TIME_FORMAT "%d-%m-%Y %H:%M:%S."
#endif

#ifndef LOGGER_TIME_PRINT_MILLISECONDS
#define LOGGER_TIME_PRINT_MILLISECONDS 1
#endif

    class StreamHandler : public Handler
    {
    public:
        StreamHandler(const std::string &name, std::ostream &out, LogLevel level) : Handler(level), out_{out}, name_{name} {}
        StreamHandler(const std::string &name, std::string &path, LogLevel level, const bool truncate = false) : Handler(level), file_{new std::ofstream{path, truncate ? std::ios::trunc : std::ios::app}}, out_{*file_}, name_{name} {}

        void PrintMessage(const std::string name, std::ostream &out, const logger::Message &msg)
        {
            auto tt = std::chrono::system_clock::to_time_t(msg.when_);
            auto when_rounded = std::chrono::system_clock::from_time_t(tt);
            if (when_rounded > msg.when_)
            {
                --tt;
                when_rounded -= std::chrono::seconds(1);
            }
            if (const auto tm = (LOGGER_USE_UTCZONE ? std::gmtime(&tt) : std::localtime(&tt)))
            {
                const int ms = std::chrono::duration_cast<std::chrono::duration<int, std::milli>>(msg.when_ - when_rounded).count();

                out << std::put_time(tm, LOGGER_TIME_FORMAT)
#if LOGGER_TIME_PRINT_MILLISECONDS
                    << std::setw(3) << std::setfill('0') << ms
#endif
#if LOGGER_TIME_PRINT_TIMEZONE
#if LOGGER_USE_UTCZONE
                    << " UTC";
#else
                    << std::put_time(tm, " %Z")
#endif
#endif
                ;
            }
            else
            {
                out << "0000-00-00 00:00:00.000";
            }

            out << ' ' << '[' << name << ']'
                << ' ' << '[' << LevelName(msg.level_) << ']'
                << ' ' << LOGGER_THREAD_NAME
                << ' ' << msg.msg_;
        }

        void LogMessage(const Message &msg) override
        {
            PrintMessage(name_, out_, msg);
            out_ << std::endl;
        }

    private:
        std::unique_ptr<std::ostream> file_;
        std::ostream &out_;
        const std::string name_;
    };

#endif

    class LogManager
    {
        LogManager() = default;
        LogManager(const LogManager &) = delete;
        LogManager(LogManager &&) = delete;
        void operator=(const LogManager &) = delete;
        void operator=(LogManager &&) = delete;

    public:
        static LogManager &Instance()
        {
            static LogManager instance;
            return instance;
        }

        void LogMessage(Message message)
        {
            std::lock_guard<std::mutex> lock{mutex_};
            for (const auto &h : handlers_)
            {
                if (h->level_ >= message.level_)
                {
                    h->LogMessage(message);
                }
            }
        }

        void AddHandler(Handler::ptr_t &&handler)
        {
            std::lock_guard<std::mutex> lock{mutex_};

            // Make sure we log at the most detailed level used
            if (level_ < handler->level_)
            {
                level_ = handler->level_;
            }
            handlers_.push_back(std::move(handler));
        }

        /*! Set handler.
         *
         * Remove any existing handlers.
         */
        void SetHandler(Handler::ptr_t &&handler)
        {
            std::lock_guard<std::mutex> lock{mutex_};
            handlers_.clear();
            level_ = handler->level_;
            handlers_.push_back(std::move(handler));
        }

        /*! Remove all existing handlers
         *
         */
        void ClearHandlers()
        {
            std::lock_guard<std::mutex> lock{mutex_};
            handlers_.clear();
            level_ = LogLevel::DISABLED;
        }

        void SetLevel(LogLevel level)
        {
            level_ = level;
        }

        LogLevel GetLoglevel() const noexcept
        {
            return level_;
        }

        bool IsRelevant(const LogLevel level) const noexcept
        {
            return !handlers_.empty() && (level <= level_);
        }

    private:
        std::vector<Handler::ptr_t> handlers_;
        std::mutex mutex_;
        LogLevel level_ = ERROR;
    };

    class Log
    {
    public:
        Log(const LogLevel level) : level_{level} {}
        ~Log()
        {
            Message message(out_.str(), level_);
            LogManager::Instance().LogMessage(message);
        }

        std::ostringstream &Line() { return out_; }

    private:
        const LogLevel level_;
        std::ostringstream out_;
    };

    void InitLogging(const char *argv0)
    {
        logger::LogLevel LOG_LEVEL = INFO;
#ifndef NDEBUG
        LOG_LEVEL = TRACE;
#endif
#ifdef __ANDROID__

        logger::LogManager::Instance().AddHandler(std::make_unique<logger::AndroidHandler>(
            argv0, LOG_LEVEL));
#else

        logger::LogManager::Instance().AddHandler(make_unique<logger::StreamHandler>(argv0, std::clog, LOG_LEVEL));
#endif
    }

} // namespace

#endif // _LOGGER_H