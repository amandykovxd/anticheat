#include "schedule.h"

static size_t ac_schedule_gcd(size_t left, size_t right)
{
    while (right != 0) {
        const size_t remainder = left % right;
        left = right;
        right = remainder;
    }
    return left;
}

uint32_t ac_schedule_delay_from_random(
    uint32_t minimum_ms,
    uint32_t maximum_ms,
    uint64_t random_value)
{
    const uint64_t width =
        maximum_ms >= minimum_ms
            ? (uint64_t)maximum_ms - minimum_ms + 1u
            : 0;

    if (width == 0) {
        return minimum_ms;
    }
    return minimum_ms + (uint32_t)(random_value % width);
}

size_t ac_schedule_coprime_step(size_t count, uint64_t candidate)
{
    size_t step;

    if (count <= 1u) {
        return 1u;
    }
    step = (size_t)(candidate % count);
    if (step == 0) {
        step = 1u;
    }
    while (ac_schedule_gcd(step, count) != 1u) {
        ++step;
        if (step >= count) {
            step = 1u;
        }
    }
    return step;
}

size_t ac_schedule_permutation_index(
    size_t position,
    size_t count,
    size_t start,
    size_t step)
{
    if (count == 0) {
        return 0;
    }
    return ((position % count) * (step % count) + (start % count)) % count;
}

size_t ac_schedule_cyclic_index(
    size_t position,
    size_t count,
    size_t start)
{
    if (count == 0) {
        return 0;
    }
    return ((position % count) + (start % count)) % count;
}
