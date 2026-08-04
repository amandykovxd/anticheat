#ifndef AC_SCHEDULE_H
#define AC_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>

uint32_t ac_schedule_delay_from_random(
    uint32_t minimum_ms,
    uint32_t maximum_ms,
    uint64_t random_value);
size_t ac_schedule_coprime_step(size_t count, uint64_t candidate);
size_t ac_schedule_permutation_index(
    size_t position,
    size_t count,
    size_t start,
    size_t step);
size_t ac_schedule_cyclic_index(
    size_t position,
    size_t count,
    size_t start);

#endif
