#include "ac.h"

#include <inttypes.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>

#define AC_ATTESTATION_FILE_LIMIT (256ull * 1024ull * 1024ull)
#define AC_ATTESTATION_DOMAIN "ac-collector-attestation-v2"

static bool ac_attestation_parse_hex_wide(
    const wchar_t *text,
    size_t byte_count,
    uint8_t *bytes_out,
    char *canonical_out)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;

    if (text == NULL || bytes_out == NULL || canonical_out == NULL ||
        wcslen(text) != byte_count * 2u) {
        return false;
    }
    for (index = 0; index < byte_count; ++index) {
        uint8_t digits[2];
        size_t digit_index;

        for (digit_index = 0; digit_index < 2u; ++digit_index) {
            const wchar_t value = text[index * 2u + digit_index];
            if (value >= L'0' && value <= L'9') {
                digits[digit_index] = (uint8_t)(value - L'0');
            } else if (value >= L'a' && value <= L'f') {
                digits[digit_index] = (uint8_t)(value - L'a' + 10);
            } else if (value >= L'A' && value <= L'F') {
                digits[digit_index] = (uint8_t)(value - L'A' + 10);
            } else {
                return false;
            }
        }
        bytes_out[index] = (uint8_t)((digits[0] << 4u) | digits[1]);
        canonical_out[index * 2u] = alphabet[digits[0]];
        canonical_out[index * 2u + 1u] = alphabet[digits[1]];
    }
    canonical_out[byte_count * 2u] = '\0';
    return true;
}

static bool ac_attestation_image_path(wchar_t **path_out)
{
    DWORD capacity = MAX_PATH;
    wchar_t *path = NULL;

    while (capacity <= 32768u) {
        wchar_t *candidate = (wchar_t *)realloc(
            path,
            (size_t)capacity * sizeof(*candidate));
        DWORD length;

        if (candidate == NULL) {
            free(path);
            return false;
        }
        path = candidate;
        SetLastError(ERROR_SUCCESS);
        length = GetModuleFileNameW(NULL, path, capacity);
        if (length == 0) {
            free(path);
            return false;
        }
        if (length < capacity - 1u ||
            (length < capacity && GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
            path[length] = L'\0';
            *path_out = path;
            return true;
        }
        capacity *= 2u;
    }
    free(path);
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return false;
}

static bool ac_attestation_read_file(
    const wchar_t *path,
    uint8_t **data_out,
    size_t *size_out,
    uint8_t digest_out[AC_SHA256_DIGEST_SIZE])
{
    HANDLE file;
    LARGE_INTEGER size;
    uint8_t *data;
    uint64_t offset = 0;

    *data_out = NULL;
    *size_out = 0;
    file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        (uint64_t)size.QuadPart > AC_ATTESTATION_FILE_LIMIT ||
        (uint64_t)size.QuadPart > SIZE_MAX) {
        CloseHandle(file);
        SetLastError(ERROR_FILE_TOO_LARGE);
        return false;
    }
    data = (uint8_t *)malloc((size_t)size.QuadPart);
    if (data == NULL) {
        CloseHandle(file);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    while (offset < (uint64_t)size.QuadPart) {
        const uint64_t remaining = (uint64_t)size.QuadPart - offset;
        const DWORD requested = remaining > 0x100000u
            ? 0x100000u : (DWORD)remaining;
        DWORD received = 0;

        if (!ReadFile(
                file,
                data + (size_t)offset,
                requested,
                &received,
                NULL) || received == 0) {
            free(data);
            CloseHandle(file);
            return false;
        }
        offset += received;
    }
    ac_sha256(data, (size_t)offset, digest_out);
    CloseHandle(file);
    *data_out = data;
    *size_out = (size_t)offset;
    return true;
}

bool ac_collector_attest(
    const wchar_t *challenge_id,
    const wchar_t *nonce,
    const wchar_t *server_session_id,
    AcCollectorAttestation *result)
{
    uint8_t challenge_bytes[AC_ATTESTATION_CHALLENGE_BYTES];
    uint8_t nonce_bytes[AC_SHA256_DIGEST_SIZE];
    uint8_t session_bytes[16];
    char session_canonical[33];
    char nonce_canonical[AC_SHA256_HEX_SIZE];
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    wchar_t *path = NULL;
    uint8_t file_digest[AC_SHA256_DIGEST_SIZE];
    uint8_t expected_digest[AC_SHA256_DIGEST_SIZE];
    uint8_t observed_digest[AC_SHA256_DIGEST_SIZE];
    uint8_t nonce_digest[AC_SHA256_DIGEST_SIZE];
    uint8_t response_digest[AC_SHA256_DIGEST_SIZE];
    AcSha256 expected_hash;
    AcSha256 observed_hash;
    AcSha256 response_hash;
    AcPeImage image;
    AcPeMask mask;
    HMODULE module;
    MODULEINFO module_info;
    uint16_t section_index;
    bool success = false;
    const size_t version_length = strlen(AC_AGENT_VERSION);

    if (result == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    memset(result, 0, sizeof(*result));
    if (!ac_attestation_parse_hex_wide(
            challenge_id,
            sizeof(challenge_bytes),
            challenge_bytes,
            result->challenge_id) ||
        !ac_attestation_parse_hex_wide(
            nonce,
            sizeof(nonce_bytes),
            nonce_bytes,
            nonce_canonical) ||
        !ac_attestation_parse_hex_wide(
            server_session_id,
            sizeof(session_bytes),
            session_bytes,
            session_canonical) ||
        version_length == 0 || version_length > UINT8_MAX) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    ac_sha256(nonce_bytes, sizeof(nonce_bytes), nonce_digest);
    ac_sha256_to_hex(nonce_digest, result->nonce_sha256);

    if (!ac_attestation_image_path(&path) ||
        !ac_attestation_read_file(
            path,
            &file_data,
            &file_size,
            file_digest) ||
        ac_pe_parse(file_data, file_size, &image) != AC_PE_OK) {
        goto cleanup;
    }
    module = GetModuleHandleW(NULL);
    if (module == NULL || !GetModuleInformation(
            GetCurrentProcess(),
            module,
            &module_info,
            (DWORD)sizeof(module_info))) {
        goto cleanup;
    }

    ac_pe_mask_init(&mask);
    if (ac_pe_mask_import_tables(&image, &mask) != AC_PE_OK) {
        ac_pe_mask_free(&mask);
        goto cleanup;
    }
    ac_sha256_init(&expected_hash);
    ac_sha256_init(&observed_hash);
    ac_sha256_update(
        &expected_hash,
        AC_ATTESTATION_DOMAIN,
        sizeof(AC_ATTESTATION_DOMAIN) - 1u);
    ac_sha256_update(
        &observed_hash,
        AC_ATTESTATION_DOMAIN,
        sizeof(AC_ATTESTATION_DOMAIN) - 1u);
    result->mapped_matches_disk = true;

    for (section_index = 0;
         section_index < image.section_count;
         ++section_index) {
        const AcPeSection *section = &image.sections[section_index];
        uint8_t *expected;
        uint8_t *observed;
        const uint64_t section_end =
            (uint64_t)section->virtual_address + section->virtual_size;
        const int64_t delta =
            (int64_t)((uint64_t)(uintptr_t)module - image.image_base);

        if (!ac_pe_section_is_executable(section) ||
            section->virtual_size == 0) {
            continue;
        }
        if (section_end > module_info.SizeOfImage ||
            section->virtual_size > AC_ATTESTATION_FILE_LIMIT) {
            ac_pe_mask_free(&mask);
            SetLastError(ERROR_BAD_EXE_FORMAT);
            goto cleanup;
        }
        if (section->raw_size < section->virtual_size &&
            !ac_pe_mask_add(
                &mask,
                section->virtual_address + section->raw_size,
                section->virtual_size - section->raw_size)) {
            ac_pe_mask_free(&mask);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        expected = (uint8_t *)malloc(section->virtual_size);
        observed = (uint8_t *)malloc(section->virtual_size);
        if (expected == NULL || observed == NULL) {
            free(expected);
            free(observed);
            ac_pe_mask_free(&mask);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        if (ac_pe_materialize_section(
                &image,
                section,
                expected,
                section->virtual_size) != AC_PE_OK ||
            ac_pe_apply_relocations(
                &image,
                section,
                expected,
                delta,
                &mask) != AC_PE_OK) {
            free(expected);
            free(observed);
            ac_pe_mask_free(&mask);
            SetLastError(ERROR_BAD_EXE_FORMAT);
            goto cleanup;
        }
        memcpy(
            observed,
            (const uint8_t *)(uintptr_t)module + section->virtual_address,
            section->virtual_size);
        ac_pe_mask_finalize(&mask);
        ac_pe_mask_zero(
            &mask,
            expected,
            section->virtual_address,
            section->virtual_size);
        ac_pe_mask_zero(
            &mask,
            observed,
            section->virtual_address,
            section->virtual_size);
        if (memcmp(expected, observed, section->virtual_size) != 0) {
            result->mapped_matches_disk = false;
        }
        ac_sha256_update(&expected_hash, section->name, sizeof(section->name));
        ac_sha256_update(
            &expected_hash,
            &section->virtual_address,
            sizeof(section->virtual_address));
        ac_sha256_update(
            &expected_hash,
            &section->virtual_size,
            sizeof(section->virtual_size));
        ac_sha256_update(&expected_hash, expected, section->virtual_size);
        ac_sha256_update(&observed_hash, section->name, sizeof(section->name));
        ac_sha256_update(
            &observed_hash,
            &section->virtual_address,
            sizeof(section->virtual_address));
        ac_sha256_update(
            &observed_hash,
            &section->virtual_size,
            sizeof(section->virtual_size));
        ac_sha256_update(&observed_hash, observed, section->virtual_size);
        ++result->executable_sections;
        result->executable_bytes += section->virtual_size;
        free(expected);
        free(observed);
    }
    ac_pe_mask_free(&mask);
    if (result->executable_sections == 0) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        goto cleanup;
    }
    ac_sha256_final(&expected_hash, expected_digest);
    ac_sha256_final(&observed_hash, observed_digest);
    ac_sha256_to_hex(file_digest, result->file_sha256);
    (void)strcpy_s(
        result->server_session_id,
        sizeof(result->server_session_id),
        session_canonical);
    (void)strcpy_s(
        result->collector_version,
        sizeof(result->collector_version),
        AC_AGENT_VERSION);
    (void)strcpy_s(
        result->collector_build_id,
        sizeof(result->collector_build_id),
        result->file_sha256);
    ac_sha256_to_hex(expected_digest, result->expected_mapped_sha256);
    ac_sha256_to_hex(observed_digest, result->observed_mapped_sha256);

    ac_sha256_init(&response_hash);
    ac_sha256_update(
        &response_hash,
        AC_ATTESTATION_DOMAIN,
        sizeof(AC_ATTESTATION_DOMAIN) - 1u);
    ac_sha256_update(&response_hash, challenge_bytes, sizeof(challenge_bytes));
    ac_sha256_update(&response_hash, nonce_bytes, sizeof(nonce_bytes));
    ac_sha256_update(&response_hash, session_bytes, sizeof(session_bytes));
    {
        const uint8_t version_length_byte = (uint8_t)version_length;
        ac_sha256_update(
            &response_hash,
            &version_length_byte,
            sizeof(version_length_byte));
    }
    ac_sha256_update(&response_hash, AC_AGENT_VERSION, version_length);
    ac_sha256_update(&response_hash, file_digest, sizeof(file_digest));
    ac_sha256_update(&response_hash, file_digest, sizeof(file_digest));
    ac_sha256_update(&response_hash, observed_digest, sizeof(observed_digest));
    ac_sha256_final(&response_hash, response_digest);
    ac_sha256_to_hex(response_digest, result->response_sha256);
    result->complete = true;
    success = true;

cleanup:
    SecureZeroMemory(nonce_bytes, sizeof(nonce_bytes));
    SecureZeroMemory(session_bytes, sizeof(session_bytes));
    SecureZeroMemory(nonce_canonical, sizeof(nonce_canonical));
    free(path);
    free(file_data);
    return success;
}

void ac_log_collector_attestation(
    AcLogger *logger,
    DWORD target_pid,
    uint64_t scan_id,
    const AcCollectorAttestation *result)
{
    char details[1536];

    if (logger == NULL || result == NULL) {
        return;
    }
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"challenge_id\":\"%s\","
        "\"server_session_id\":\"%s\",\"collector_version\":\"%s\","
        "\"collector_build_id\":\"%s\","
        "\"nonce_sha256\":\"%s\",\"file_sha256\":\"%s\","
        "\"expected_mapped_sha256\":\"%s\","
        "\"observed_mapped_sha256\":\"%s\","
        "\"response_sha256\":\"%s\",\"executable_sections\":%zu,"
        "\"executable_bytes\":%" PRIu64 ",\"mapped_matches_disk\":%s,"
        "\"complete\":%s,\"algorithm\":\"sha256\","
        "\"normalization\":\"pe_relocations_iat_unbacked_masked_v1\"}",
        scan_id,
        result->challenge_id,
        result->server_session_id,
        result->collector_version,
        result->collector_build_id,
        result->nonce_sha256,
        result->file_sha256,
        result->expected_mapped_sha256,
        result->observed_mapped_sha256,
        result->response_sha256,
        result->executable_sections,
        result->executable_bytes,
        result->mapped_matches_disk ? "true" : "false",
        result->complete ? "true" : "false");
    ac_log_event(
        logger,
        result->mapped_matches_disk
            ? AC_SEVERITY_INFO : AC_SEVERITY_HIGH,
        "collector_attestation_observed",
        target_pid,
        details);
}
