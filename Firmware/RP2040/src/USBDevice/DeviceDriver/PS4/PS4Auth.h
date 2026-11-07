#ifndef OGXM_PS4_AUTH_H
#define OGXM_PS4_AUTH_H

#include <cstddef>
#include <cstdint>

namespace PS4Auth {

constexpr size_t SERIAL_SIZE = 16;
constexpr size_t SIGNATURE_SIZE = 256;
constexpr size_t MODULUS_SIZE = 256;
constexpr size_t EXPONENT_SIZE = 4;
constexpr size_t PRIME_SIZE = 128;
constexpr size_t PAYLOAD_SIZE = SERIAL_SIZE + SIGNATURE_SIZE + MODULUS_SIZE + EXPONENT_SIZE + PRIME_SIZE * 2;
constexpr size_t UPLOAD_CHUNK_SIZE = 48;

// Bundle order: serial, certificate signature, RSA modulus, exponent, p, q.
// Parses the bundle and checks the RSA key in RAM; does not touch flash.
bool validate_bundle(const uint8_t* data, size_t length);
// Writes the bundle to NVS. Flash erase/program is not safe while Core1 (BT) or
// USB/timer IRQs are live, so call this only after board_api::usb::disconnect_all()
// and reboot afterwards.
bool store_bundle(const uint8_t* data, size_t length);
bool has_bundle();
// True if stored keys load and the RSA key can be initialized.
bool keys_valid();
void process();
void reset();
void handle_set_report(uint8_t report_id, const uint8_t* data, size_t length);
uint16_t handle_get_report(uint8_t report_id, uint8_t* data, uint16_t capacity);

} // namespace PS4Auth

#endif
