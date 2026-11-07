#include "PS4Auth.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

#include "UserSettings/NVSTool.h"
#include "USBDevice/DeviceDriver/PS4/PS4Responses.h"
#include "pico/rand.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

namespace PS4Auth {
namespace {

constexpr size_t kStoredChunk = 48;
constexpr size_t kChunkCount = (PAYLOAD_SIZE + kStoredChunk - 1) / kStoredChunk;
constexpr uint32_t kValidMarker = 0x34534B50; // "PKS4"
constexpr uint8_t kSetPayload = 0xF0;
constexpr uint8_t kGetSignature = 0xF1;
constexpr uint8_t kGetState = 0xF2;
constexpr uint8_t kReset = 0xF3;
constexpr uint8_t kCalibration = 0x02;
constexpr uint8_t kDefinition = 0x03;
constexpr uint8_t kMac = 0x12;
constexpr uint8_t kVersion = 0xA3;

struct Bundle {
	std::array<uint8_t, SERIAL_SIZE> serial{};
	std::array<uint8_t, SIGNATURE_SIZE> signature{};
	std::array<uint8_t, MODULUS_SIZE> modulus{};
	std::array<uint8_t, EXPONENT_SIZE> exponent{};
	std::array<uint8_t, PRIME_SIZE> p{};
	std::array<uint8_t, PRIME_SIZE> q{};
};

Bundle bundle;
bool bundle_loaded = false;
mbedtls_rsa_context rsa;
bool rsa_initialized = false;
bool rsa_context_live = false;
std::array<uint8_t, 1064> auth_response{};
uint8_t nonce_id = 0;
uint8_t response_chunk = 0;
uint8_t signing_state = 16; // 0 = signed and ready; 16 = pending/invalid
bool sign_pending = false;

uint32_t crc32(const uint8_t* bytes, size_t length)
{
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < length; ++i) {
		crc ^= bytes[i];
		for (unsigned bit = 0; bit < 8; ++bit)
			crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
	}
	return ~crc;
}

void parse_bundle(const uint8_t* raw)
{
	size_t offset = 0;
	std::memcpy(bundle.serial.data(), raw + offset, SERIAL_SIZE); offset += SERIAL_SIZE;
	std::memcpy(bundle.signature.data(), raw + offset, SIGNATURE_SIZE); offset += SIGNATURE_SIZE;
	std::memcpy(bundle.modulus.data(), raw + offset, MODULUS_SIZE); offset += MODULUS_SIZE;
	std::memcpy(bundle.exponent.data(), raw + offset, EXPONENT_SIZE); offset += EXPONENT_SIZE;
	std::memcpy(bundle.p.data(), raw + offset, PRIME_SIZE); offset += PRIME_SIZE;
	std::memcpy(bundle.q.data(), raw + offset, PRIME_SIZE);
	bundle_loaded = true;
}

bool load_bundle()
{
	NVSTool& nvs = NVSTool::get_instance();
	uint32_t marker = 0;
	if (!nvs.read("PS4MARK", &marker, sizeof(marker)) || marker != kValidMarker)
		return false;
	std::array<uint8_t, PAYLOAD_SIZE> raw{};
	for (size_t i = 0; i < kChunkCount; ++i) {
		char key[9];
		std::snprintf(key, sizeof(key), "PS4K%02u", static_cast<unsigned>(i));
		std::array<uint8_t, kStoredChunk> part{};
		if (!nvs.read(key, part.data(), part.size()))
			return false;
		const size_t offset = i * kStoredChunk;
		const size_t count = (PAYLOAD_SIZE - offset < kStoredChunk) ? PAYLOAD_SIZE - offset : kStoredChunk;
		std::memcpy(raw.data() + offset, part.data(), count);
	}
	parse_bundle(raw.data());
	return true;
}

int rng_callback(void*, unsigned char* output, size_t length)
{
	while (length) {
		const uint32_t value = get_rand_32();
		const size_t count = length < sizeof(value) ? length : sizeof(value);
		std::memcpy(output, &value, count);
		output += count;
		length -= count;
	}
	return 0;
}

bool initialize_rsa()
{
	if (!bundle_loaded && !load_bundle()) return false;
	if (rsa_context_live) mbedtls_rsa_free(&rsa);
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
	rsa_context_live = true;
	mbedtls_mpi N, E, P, Q;
	mbedtls_mpi_init(&N); mbedtls_mpi_init(&E); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
	// GP2040-CE's key bundle contains native little-endian mbedTLS MPI limbs.
	// Convert those byte arrays to the big-endian form expected by mpi_read_binary.
	auto read_native_mpi = [](mbedtls_mpi* mpi, const uint8_t* bytes, size_t length) {
		std::array<uint8_t, MODULUS_SIZE> be{};
		if (length > be.size()) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
		std::reverse_copy(bytes, bytes + length, be.begin() + (be.size() - length));
		return mbedtls_mpi_read_binary(mpi, be.data() + (be.size() - length), length);
	};
	int rc = read_native_mpi(&N, bundle.modulus.data(), bundle.modulus.size());
	if (rc == 0) rc = read_native_mpi(&E, bundle.exponent.data(), bundle.exponent.size());
	if (rc == 0) rc = read_native_mpi(&P, bundle.p.data(), bundle.p.size());
	if (rc == 0) rc = read_native_mpi(&Q, bundle.q.data(), bundle.q.size());
	if (rc == 0) rc = mbedtls_rsa_import(&rsa, &N, &P, &Q, nullptr, &E);
	if (rc == 0) rc = mbedtls_rsa_complete(&rsa);
	mbedtls_mpi_free(&N); mbedtls_mpi_free(&E); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
	rsa_initialized = (rc == 0);
	if (!rsa_initialized) {
		mbedtls_rsa_free(&rsa);
		rsa_context_live = false;
	}
	return rsa_initialized;
}

void sign_nonce()
{
	signing_state = 16;
	if (!rsa_initialized && !initialize_rsa()) return;
	uint8_t hash[32];
	mbedtls_sha256(auth_response.data(), 256, hash, 0);
	if (mbedtls_rsa_rsassa_pss_sign(&rsa, rng_callback, nullptr, MBEDTLS_RSA_PRIVATE,
		MBEDTLS_MD_SHA256, sizeof(hash), hash, auth_response.data()) != 0) return;

	std::memcpy(auth_response.data() + 256, bundle.serial.data(), SERIAL_SIZE);
	if (mbedtls_rsa_export_raw(&rsa,
		auth_response.data() + 272, 256, nullptr, 0, nullptr, 0,
		nullptr, 0, auth_response.data() + 528, 256) != 0) return;
	std::memcpy(auth_response.data() + 784, bundle.signature.data(), SIGNATURE_SIZE);
	std::memset(auth_response.data() + 1040, 0, 24);
	signing_state = 0;
}

} // namespace

bool validate_bundle(const uint8_t* data, size_t length)
{
	if (data == nullptr || length != PAYLOAD_SIZE) return false;
	parse_bundle(data);
	if (initialize_rsa()) return true;
	bundle_loaded = false;
	return false;
}

bool store_bundle(const uint8_t* data, size_t length)
{
	if (data == nullptr || length != PAYLOAD_SIZE) return false;
	NVSTool& nvs = NVSTool::get_instance();
	uint32_t invalid = 0;
	if (!nvs.write("PS4MARK", &invalid, sizeof(invalid))) return false;
	for (size_t i = 0; i < kChunkCount; ++i) {
		char key[9];
		std::snprintf(key, sizeof(key), "PS4K%02u", static_cast<unsigned>(i));
		std::array<uint8_t, kStoredChunk> part{};
		part.fill(0xFF);
		const size_t offset = i * kStoredChunk;
		const size_t count = (length - offset < kStoredChunk) ? length - offset : kStoredChunk;
		std::memcpy(part.data(), data + offset, count);
		if (!nvs.write(key, part.data(), part.size())) return false;
	}
	if (!nvs.write("PS4MARK", &kValidMarker, sizeof(kValidMarker))) return false;
	// The key was already checked by validate_bundle(); just confirm the read-back.
	bundle_loaded = false;
	return load_bundle();
}

bool keys_valid()
{
	return (bundle_loaded || load_bundle()) && initialize_rsa();
}

bool has_bundle()
{
	return (bundle_loaded || load_bundle()) && (rsa_initialized || initialize_rsa());
}

void process()
{
	if (sign_pending) {
		sign_pending = false;
		sign_nonce();
	}
}

void reset()
{
	signing_state = 16;
	sign_pending = false;
	response_chunk = 0;
	std::memset(auth_response.data(), 0, auth_response.size());
}

void handle_set_report(uint8_t report_id, const uint8_t* data, size_t length)
{
	if (data == nullptr) return;
	if (report_id == kReset) { reset(); return; }
	if (report_id != kSetPayload || length != 63 || data[1] > 4) return;
	uint8_t check[64];
	check[0] = report_id;
	std::memcpy(check + 1, data, length);
	uint32_t received;
	std::memcpy(&received, check + 60, sizeof(received));
	if (crc32(check, 60) != received) return;
	const uint8_t id = data[0];
	const uint8_t page = data[1];
	if (page == 0) { nonce_id = id; response_chunk = 0; signing_state = 16; }
	if (id != nonce_id) { reset(); return; }
	const size_t count = page == 4 ? 32 : 56;
	std::memcpy(auth_response.data() + static_cast<size_t>(page) * 56, data + 3, count);
	if (page == 4) sign_pending = true;
}

uint16_t handle_get_report(uint8_t report_id, uint8_t* data, uint16_t capacity)
{
	if (data == nullptr) return 0;
	if (report_id == kGetSignature) {
		if (capacity < 63 || signing_state != 0 || response_chunk >= 19) return 0;
		data[0] = nonce_id;
		data[1] = response_chunk;
		data[2] = 0;
		std::memcpy(data + 3, auth_response.data() + static_cast<size_t>(response_chunk) * 56, 56);
		uint8_t packet[60];
		packet[0] = report_id;
		std::memcpy(packet + 1, data, 59);
		const uint32_t crc = crc32(packet, sizeof(packet));
		std::memcpy(data + 59, &crc, sizeof(crc));
		if (++response_chunk == 19) reset();
		return 63;
	}
	if (report_id == kGetState) {
		if (capacity < 15) return 0;
		data[0] = nonce_id; data[1] = signing_state;
		std::memset(data + 2, 0, 9);
		uint8_t packet[12]; packet[0] = report_id; std::memcpy(packet + 1, data, 11);
		const uint32_t crc = crc32(packet, sizeof(packet));
		std::memcpy(data + 11, &crc, sizeof(crc));
		return 15;
	}
	if (report_id == kReset) {
		if (capacity < 7) return 0;
		const uint8_t response[7] = {0, 0x38, 0x38, 0, 0, 0, 0};
		std::memcpy(data, response, sizeof(response));
		reset();
		return sizeof(response);
	}
	// Controller identity reports the console reads during setup (values from GP2040-CE).
	if (report_id == kCalibration || report_id == kMac || report_id == kVersion) {
		const uint8_t* src = report_id == kCalibration ? PS4Responses::kCalibration0x02
			: report_id == kMac ? PS4Responses::kMac0x12 : PS4Responses::kVersion0xA3;
		const size_t len = report_id == kCalibration ? sizeof(PS4Responses::kCalibration0x02)
			: report_id == kMac ? sizeof(PS4Responses::kMac0x12) : sizeof(PS4Responses::kVersion0xA3);
		if (capacity < len) return 0;
		std::memcpy(data, src, len);
		return static_cast<uint16_t>(len);
	}
	if (report_id == kDefinition) {
		// Layout matches GP2040-CE PS4ControllerConfig (47 bytes, packed).
		struct __attribute__((packed)) Definition {
			uint16_t hid_usage = 0x2721;
			uint8_t mystery0 = 0x04;
			uint8_t features = 0xEF;   // controller, motion, LED, rumble, unknown, touchpad, unknown
			uint8_t controller_type = 0; // PS4_CONTROLLER
			uint8_t touchpad_param[2] = {0x2c, 0x56};
			uint16_t gyro_range = 0x0008;
			uint16_t gyro_res_denom = 0x003D;
			uint16_t gyro_res_numer = 0x03E8;
			uint16_t accel_range = 0x0004;
			uint16_t accel_res_per_g = 0x7FFF;
			uint16_t magic_id = 0x0d0d;
			uint8_t mystery1[4] = {0, 0, 0, 0};
			uint8_t wheel_param[3] = {0x0D, 0x84, 0x03};
			uint8_t mystery2[21] = {0};
		};
		static_assert(sizeof(Definition) == 47, "PS4 definition report size");
		if (capacity < sizeof(Definition)) return 0;
		Definition def{};
		std::memcpy(data, &def, sizeof(def));
		return static_cast<uint16_t>(sizeof(def));
	}
	// Preserve the existing PS4 driver's zero-filled response behavior for
	// feature reports that are not part of the authentication exchange.
	std::memset(data, 0, capacity);
	return capacity;
}

} // namespace PS4Auth
