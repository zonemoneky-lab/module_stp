#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <queue>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

class EventLoop {
public:
    using Task = std::function<void()>;
    using Clock = std::chrono::steady_clock;
    using TimerId = std::uint64_t;

    bool Post(Task task) {
        return PostAt(Clock::now(), std::move(task), false, {});
    }

    bool PostDelay(Task task, std::chrono::milliseconds delay) {
        return PostAt(Clock::now() + delay, std::move(task), false, {});
    }

    template <typename F>
    auto PostFuture(F&& func)
        -> std::future<std::invoke_result_t<std::decay_t<F>&>> {
        return PostFutureAt(Clock::now(), std::forward<F>(func));
    }

    template <typename F>
    auto PostFutureDelay(F&& func, std::chrono::milliseconds delay)
        -> std::future<std::invoke_result_t<std::decay_t<F>&>> {
        return PostFutureAt(Clock::now() + delay, std::forward<F>(func));
    }

    TimerId PostInterval(Task task, std::chrono::milliseconds interval) {
        if (!task || interval.count() <= 0 || stopped_) {
            return 0;
        }

        TimerId id = next_timer_id_++;

        tasks_.push(Item{
            Clock::now() + interval,
            next_seq_++,
            id,
            true,
            interval,
            std::move(task)
        });

        active_intervals_.insert(id);
        return id;
    }

    void Cancel(TimerId id) {
        active_intervals_.erase(id);
    }

    void Poll() {
        if (stopped_) {
            return;
        }

        const auto now = Clock::now();

        while (!tasks_.empty() && tasks_.top().time <= now) {
            Item item = tasks_.top();
            tasks_.pop();

            if (item.repeat && active_intervals_.count(item.id) == 0) {
                continue;
            }

            if (item.task) {
                item.task();
            }

            if (stopped_) {
                break;
            }

            if (item.repeat && active_intervals_.count(item.id) != 0) {
                item.time = Clock::now() + item.interval;
                item.seq = next_seq_++;
                tasks_.push(std::move(item));
            }
        }
    }

    void Stop() {
        stopped_ = true;

        while (!tasks_.empty()) {
            tasks_.pop();
        }

        active_intervals_.clear();
    }

    bool Empty() const {
        return tasks_.empty();
    }

private:
    struct Item {
        Clock::time_point time;
        std::uint64_t seq;
        TimerId id;
        bool repeat;
        std::chrono::milliseconds interval;
        Task task;
    };

    struct Compare {
        bool operator()(const Item& a, const Item& b) const {
            if (a.time == b.time) {
                return a.seq > b.seq;
            }

            return a.time > b.time;
        }
    };

    bool PostAt(
        Clock::time_point time,
        Task task,
        bool repeat,
        std::chrono::milliseconds interval
    ) {
        if (!task || stopped_) {
            return false;
        }

        tasks_.push(Item{
            time,
            next_seq_++,
            0,
            repeat,
            interval,
            std::move(task)
        });

        return true;
    }

    template <typename F>
    auto PostFutureAt(Clock::time_point time, F&& func)
        -> std::future<std::invoke_result_t<std::decay_t<F>&>> {
        using Fn = std::decay_t<F>;
        using R = std::invoke_result_t<Fn&>;

        auto promise = std::make_shared<std::promise<R>>();
        auto future = promise->get_future();

        if (stopped_) {
            promise->set_exception(std::make_exception_ptr(
                std::runtime_error("EventLoop is stopped")
            ));
            return future;
        }

        Fn fn(std::forward<F>(func));

        bool ok = PostAt(
            time,
            [promise, fn = std::move(fn)]() mutable {
                try {
                    if constexpr (std::is_void_v<R>) {
                        fn();
                        promise->set_value();
                    } else {
                        promise->set_value(fn());
                    }
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            },
            false,
            {}
        );

        if (!ok) {
            promise->set_exception(std::make_exception_ptr(
                std::runtime_error("failed to post future task")
            ));
        }

        return future;
    }

private:
    std::priority_queue<Item, std::vector<Item>, Compare> tasks_;
    std::unordered_set<TimerId> active_intervals_;

    std::uint64_t next_seq_ = 0;
    TimerId next_timer_id_ = 1;
    bool stopped_ = false;
};
