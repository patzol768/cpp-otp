/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include "cotp/otp_uri.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#ifndef NO_OPENSSL
#include <openssl/evp.h>
#endif

#define OTP_MIN_DIGITS 3
#define OTP_MAX_DIGITS 8	/* uint64_t could allow 19, but the way how generate() works, not really allows more then 8 */

namespace cotp
{

// prints a byte vector as hex string, values separated by space
std::string to_string(std::vector<char> bytes);

// used for differentiation on which method you are using. Necessary
// when you go to generate a URI.
enum class OTP_type
{
	OTP, 
	TOTP,
	HOTP
};

typedef std::vector<char> (*OTP_algorithm_ptr)(std::vector<char> const&, std::vector<char> const&);

struct Algo_info
{
	std::string name;
	OTP_algorithm_ptr algo;
	size_t bits;
};

// almost all functions have a form of error they can return
// please check accordingly, and look at cotp.c for information
// about the various errors. Rule of thumb: If return 0, you have
// an error.
class OTP {
	private:
		static const std::string base32_chars;
		std::string m_issuer;
		std::string m_account;

	protected:
		static std::map<std::string, Algo_info> otp_algorithm_map;

		size_t m_digits;
		size_t m_bits;
		
		OTP_type m_method;
		OTP_algorithm_ptr m_algo;
		
		std::string m_digest_algo_name;
		std::string m_base32_secret;
		
		std::string build_uri(std::string const& otp_type, std::map<std::string, std::string> const& additional_args) const;

	public:
		OTP(std::string const& base32_secret, std::string const& algo, size_t digits);
		OTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits);
		~OTP() = default;

	    OTP(const OTP&) = delete;                  // copy constructor
	    OTP& operator=(const OTP& other) = delete; // assignment operator
	    OTP(OTP&& other);                          // move constructor
	    OTP& operator=(OTP&& other);               // move assignment operator

	    // used by build_uri()
	    void set_issuer(std::string const& value);

	    // used by build_uri()
	    void set_account(std::string const& value);

	    std::string const& get_issuer() const;
	    std::string const& get_account() const;

		// generates an otp
		// returns the integer, outputs the string version via output var
		std::string generate(uint64_t input) const;
		
		// converts the byte secret from base32 to the actual data
		std::vector<char> byte_secret() const;
		
		// used internally, generates a byte string out of an 4-byte int
		// ints need to be at least 4 bytes.
		static std::vector<char> to_bytes(uint64_t integer);
		
		// generates a valid base32 number given len as size
		static std::string random_base32(size_t len);

		// builds a valid, url-safe URI which is used for applications such as QR codes.
		virtual std::string build_uri() const = 0;

		// returns the current code
		virtual std::string code() const = 0;

		// prints to stream
		virtual std::ostream& print(std::ostream& os) const;

#ifndef NO_QR
		// helper for qr code creation
		std::string get_qr_string() const;
#endif

		// registers hmac algorithm
		bool register_hmac_algo(std::string const& name, OTP_algorithm_ptr const algo, size_t bits);
};

typedef std::shared_ptr<OTP> OTP_ptr;

class TOTP : public OTP {
	friend std::ostream& operator<<(std::ostream& os, TOTP const& obj);

	public:
		TOTP(std::string const& base32_secret, std::string const& algo, size_t digits, size_t interval);
		TOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits, size_t interval);
		~TOTP() = default;

	    TOTP(const TOTP&) = delete;                  // copy constructor
	    TOTP& operator=(const TOTP& other) = delete; // assignment operator
	    TOTP(TOTP&& other);                          // move constructor
	    TOTP& operator=(TOTP&& other);               // move assignment operator

	    static OTP_ptr create(OTP_URI const& uri);

		// compares using data as instructions, key as comparison data,
		bool compare(std::string const& key, size_t increment, uint64_t for_time) const;

		// compares using data as instructions, key as comparison data,
		bool compare(uint64_t key, size_t increment, uint64_t for_time) const;

		// generates a code at a certain timecode
		std::string code_at(uint64_t for_time, size_t counter_offset) const;
		
		// generates a code at the current time
		// before using, please srand(time(NULL)); (seed the C random generator)
		std::string code() const override;

		// verifys an otp for the timecode given in a valid window
		bool verify(std::string const& key, uint64_t for_time, size_t valid_window) const;
		
		// verifys an otp for the timecode given in a valid window
		bool verify(uint64_t key, uint64_t for_time, size_t valid_window) const;

		// verifys an otp for current time in a valid window
		bool verify(std::string const& key, size_t valid_window) const;
		
		// verifys an otp for current time in a valid window
		bool verify(uint64_t key, size_t valid_window) const;
		
		// calculates time a key has to live from a point in time, considering timeblocks
		unsigned int valid_until(uint64_t for_time, size_t valid_window) const;

		// remaining seconds from the timeblock of the given time
		unsigned int seconds_to_next_code(uint64_t for_time) const;

		// remaining seconds from the current timeblock
		unsigned int seconds_to_next_code() const;

		// generates a timecode for the given time
		int timecode(uint64_t for_time) const;

		// builds a valid, url-safe URI which is used for applications such as QR codes.
		std::string build_uri() const override;

		// prints to stream
		std::ostream& print(std::ostream& os) const override;

	private:
		size_t m_interval;
};

class HOTP : public OTP {
	friend std::ostream& operator<<(std::ostream& os, HOTP const& obj);
	
	private:
		size_t m_counter;

	public:
		HOTP(std::string const& base32_secret, std::string const& algo, size_t digits);
		HOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits);
		~HOTP() = default;

	    HOTP(const HOTP&) = delete;                  // copy constructor
	    HOTP& operator=(const HOTP& other) = delete; // assignment operator
	    HOTP(HOTP&& other);                          // move constructor
	    HOTP& operator=(HOTP&& other);               // move assignment operator

	    static OTP_ptr create(OTP_URI const& uri);

	    void set_counter(size_t value);
	    size_t get_counter() const;

		// compares using data as instructions, key as comparison data,
		bool compare(std::string const& key) const;

		// compares using data as instructions, key as comparison data,
		bool compare(uint64_t key) const;

		// generates a otp at current counter
		std::string code() const override;

		// generates a otp at a certain number (number of hits)
		std::string code_at(size_t counter) const;
		
		// verifies the key generated with the current counter server-side
		bool verify(std::string const& key) const;

		// verifies the key generated with the current counter server-side
		bool verify(uint64_t key) const;

		// builds a valid, url-safe URI which is used for applications such as QR codes.
		std::string build_uri() const override;

		// prints to stream
		std::ostream& print(std::ostream& os) const override;
};

}
