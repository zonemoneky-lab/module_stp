#include <chrono>
#include <cstdint>
#include <functional>
#include <queue>
#include <unordered_set>
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

private:
    std::priority_queue<Item, std::vector<Item>, Compare> tasks_;
    std::unordered_set<TimerId> active_intervals_;

    std::uint64_t next_seq_ = 0;
    TimerId next_timer_id_ = 1;
    bool stopped_ = false;
};