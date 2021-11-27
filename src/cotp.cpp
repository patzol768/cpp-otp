/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#include "cotp/cotp.hpp"
#include "cotp/otp_factory.hpp"

#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifndef NO_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

static void init_lib() __attribute__((constructor));

static void init_lib()
{
	unsigned int seed;
    size_t size = sizeof(seed);

    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
    if(urandom)
    {
        urandom.read((char*)(&seed), size);

        if (!urandom)
        {
	    	// fallback to the too simply time based
			seed = time(NULL);
        }

        urandom.close();
    }
    else
    {
    	// fallback to the too simply time based
		seed = time(NULL);
    }

    srand(seed);

	cotp::OTP_factory::get_instance().register_named("hotp", &cotp::HOTP::create);
	cotp::OTP_factory::get_instance().register_named("totp", &cotp::TOTP::create);
}

namespace cotp {

#ifndef NO_OPENSSL
// ================================
// HMAC with openssl
// ================================

static std::vector<char> hmac(std::vector<char> const& byte_secret, std::vector<char> const& byte_string, const EVP_MD *evp_md)
{
	u_char hmac_result[EVP_MAX_MD_SIZE];
	u_int hmac_size;

	bool hmac_success = HMAC(evp_md, byte_secret.data(), byte_secret.size(), (const unsigned char*)byte_string.data(), byte_string.size(), hmac_result, &hmac_size) != nullptr;

	if (!hmac_success)
	{
		throw std::logic_error("hmac failed");
	}

	return std::vector<char>(hmac_result, hmac_result + hmac_size);
}

static std::vector<char> hmac_algo_sha1(std::vector<char> const& byte_secret, std::vector<char> const& byte_string)
{
	return hmac(byte_secret, byte_string, EVP_sha1());
}

static std::vector<char> hmac_algo_sha256(std::vector<char> const& byte_secret, std::vector<char> const& byte_string)
{
	return hmac(byte_secret, byte_string, EVP_sha256());
}

static std::vector<char> hmac_algo_sha512(std::vector<char> const& byte_secret, std::vector<char> const& byte_string)
{
	return hmac(byte_secret, byte_string, EVP_sha512());
}
#endif

// ================================
// tools
// ================================

std::string to_string(std::vector<char> bytes)
{
	std::ostringstream oss;

	for(auto const c : bytes)
	{
		oss << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << ((u_int)c&0xff) << " ";
	}

	return oss.str();
}

// ================================
// OTP
// ================================

const std::string OTP::base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::map<std::string, Algo_info> OTP::otp_algorithm_map =
{
#ifndef NO_OPENSSL
	{"SHA1", {"SHA1", &hmac_algo_sha1, 160}},
	{"SHA256", {"SHA256", &hmac_algo_sha256, 256}},
	{"SHA512", {"SHA512", &hmac_algo_sha512, 512}}
#endif
};

OTP::OTP(std::string const& base32_secret, std::string const& algo, size_t digits)
:OTP(base32_secret, otp_algorithm_map.at(algo).bits, otp_algorithm_map.at(algo).algo, otp_algorithm_map.at(algo).name, digits)
{
}

OTP::OTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits)
: m_digits(digits)
, m_bits(bits)
, m_method(OTP_type::OTP)
, m_algo(algo)
, m_digest_algo_name(digest_algo_name)
, m_base32_secret(base32_secret)
{
	if (base32_secret.empty()
		|| m_digest_algo_name.empty()
		|| bits%8 != 0
		|| bits < 8*(15+3+1)	// due to the way how "dynamic truncate" (see RFC) works
		|| algo == nullptr
		|| digits < OTP_MIN_DIGITS
		|| digits > OTP_MAX_DIGITS)
	{
		throw std::logic_error("otp invalid param");
	}
}

OTP::OTP(OTP&& other)
{
	*this = std::move(other);
}

OTP& OTP::operator=(OTP&& other)
{
	if (this == &other)
		return *this;

	m_digits = other.m_digits;
	m_bits = other.m_bits;
	m_method = other.m_method;
	m_algo = other.m_algo;
	m_digest_algo_name = std::move(other.m_digest_algo_name);
	m_base32_secret = std::move(other.m_base32_secret);

	return *this;
}

void OTP::set_issuer(std::string const& value)
{
	m_issuer = value;
}

void OTP::set_account(std::string const& value)
{
	m_account = value;
}

std::string const& OTP::get_issuer() const
{
	return m_issuer;
}

std::string const& OTP::get_account() const
{
	return m_account;
}

std::string OTP::generate(uint64_t input) const
{
	auto v_byte_string = to_bytes(input);
	auto v_byte_secret = byte_secret();

	auto v_hmac = m_algo(v_byte_secret, v_byte_string);

	// de-SHA size
	if (v_hmac.size() != m_bits / 8)
	{
		throw std::logic_error("hmac size mismatch");
	}
	
	// gather hmac's offset, piece together code
	int offset = (v_hmac[v_hmac.size() - 1] & 0xF);
	uint64_t code =
		((v_hmac[offset] & 0x7F) << 24 |
		(v_hmac[offset+1] & 0xFF) << 16 |
		(v_hmac[offset+2] & 0xFF) << 8 |
		(v_hmac[offset+3] & 0xFF));
	code %= (uint64_t)pow(10, m_digits);

	auto code_str = std::to_string(code);

	while(code_str.size() < m_digits)
	{
		code_str = "0" + code_str;
	}

	return code_str;
}

std::vector<char> OTP::byte_secret() const
{
	std::vector<char> out_bytes(m_base32_secret.size() * 5 / 8, 0);

	int n = 5;
	for (size_t i = 0; ; i++)
	{
		n = -1;
		out_bytes[i*5] = 0;
		for (int block=0; block<8; block++)
		{
			int offset = (3 - (5*block) % 8);
			int octet = (block*5) / 8;
			
			unsigned int c = m_base32_secret[i*8+block];
			if (c >= 'A' && c <= 'Z')
				n = c - 'A';
			
			if (c >= '2' && c <= '7')
				n = 26 + c - '2';
			
			if (n < 0)
			{
				n = octet;
				break;
			}
			out_bytes[i*5+octet] |= -offset > 0 ? n >> -offset : n << offset;
			
			if (offset < 0)
				out_bytes[i*5+octet+1] = -(8 + offset) > 0 ? n >> -(8 + offset) : n << (8 + offset);
		}
		if(n < 5)
			break;
	}
	
	return out_bytes;
}

std::vector<char> OTP::to_bytes(uint64_t value)
{
	std::vector<char> out_bytes(8, 0);

	for(size_t i = 7; i > 7 - sizeof(int); --i)
	{
		out_bytes[i] = value&0xff;
		value >>= 8;
	}

	return out_bytes;
}

std::string OTP::random_base32(size_t len)
{
	len = len > 0 ? len : 16;

	std::string out_str;
	out_str.reserve(len);

	for (size_t i = 0; i < len; i++)
	{
		out_str += base32_chars[rand()%32];
	}

	return out_str;
}

std::string OTP::build_uri() const
{
	return build_uri("otp", {});
}

std::string OTP::build_uri(std::string const& otp_type, std::map<std::string, std::string> const& additional_args) const
{
	OTP_URI uri;

    uri.set_type(otp_type);
    uri.set_account(m_account);
    uri.set_secret(m_base32_secret);
    uri.set_issuer(m_issuer);
    uri.set_algorithm(m_digest_algo_name);
    uri.set_digits(m_digits);

    if (additional_args.find("counter") != additional_args.end())
    {
	    uri.set_counter(stoull(additional_args.at("counter")));
	}

    if (additional_args.find("period") != additional_args.end())
    {
	    uri.set_counter(stoul(additional_args.at("period")));
	}

	return uri.get_uri();
}

#ifndef NO_QR

std::string OTP::get_qr_string() const
{
	return build_uri();
}

#endif

bool OTP::register_hmac_algo(std::string const& name, OTP_algorithm_ptr const algo, size_t bits)
{
	if (name.empty()
		|| algo == nullptr
		|| bits % 8 != 0)
	{
		throw std::logic_error("hmac algo registration failure");
	}

	if (otp_algorithm_map.find(name) == otp_algorithm_map.end())
	{
		otp_algorithm_map.insert({name, {name, algo, bits}});
		return true;
	}

	return false;
}

std::ostream& OTP::print(std::ostream& os) const
{
	os << "digits: " << m_digits << std::endl;
	os << "bits: " << m_bits << std::endl;
	os << "digest: " << m_digest_algo_name << std::endl;
	os << "base32 secret: " << m_base32_secret << std::endl;
	os << "issuer: " << m_issuer << std::endl;
	os << "account: " << m_account << std::endl;

	return os;
}

// ================================
// TOTP
// ================================

TOTP::TOTP(std::string const& base32_secret, std::string const& algo, size_t digits, size_t interval)
:TOTP(base32_secret, otp_algorithm_map.at(algo).bits, otp_algorithm_map.at(algo).algo, otp_algorithm_map.at(algo).name, digits, interval)
{
}

TOTP::TOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits, size_t interval)
: OTP(base32_secret, bits, algo, digest_algo_name, digits)
, m_interval(interval)
{
	m_method = OTP_type::TOTP;
}

TOTP::TOTP(TOTP&& other)
: OTP(std::move(other)) 
{
	*this = std::move(other);
}

TOTP& TOTP::operator=(TOTP&& other)
{
	OTP::operator=(std::move(other));

	return *this;
}

OTP_ptr TOTP::create(OTP_URI const& uri)
{
	auto otp = std::make_shared<TOTP>(uri.get_secret(), uri.get_algorithm(), uri.get_digits(), uri.get_period());

	otp->set_issuer(uri.get_issuer());
	otp->set_account(uri.get_account());

	return otp;
}

bool TOTP::compare(std::string const& key, size_t increment, uint64_t for_time) const
{
	auto time_str = code_at(for_time, increment);

	return (key == time_str);
}

bool TOTP::compare(uint64_t key, size_t increment, uint64_t for_time) const
{
	return compare(std::to_string(key), increment, for_time);
}

std::string TOTP::code_at(uint64_t for_time, size_t counter_offset) const
{
	return generate(timecode(for_time) + counter_offset);
}

std::string TOTP::code() const
{
	return generate(timecode(time(NULL)));
}

bool TOTP::verify(std::string const& key, uint64_t for_time, size_t valid_window) const
{
	if (valid_window < 0)
	{
		return false;
	}

	if (valid_window > 0)
	{
		for (int i = -valid_window; i < (int)valid_window; i++)
		{
			if (compare(key, i, for_time))
			{
				return true;
			}
		}
		return false;
	}

	return compare(key, 0, for_time);
}

bool TOTP::verify(uint64_t key, uint64_t for_time, size_t valid_window) const
{
	auto key_str = std::to_string(key);

	while(key_str.size() < m_digits)
	{
		key_str = "0" + key_str;
	}

	return verify(key_str, for_time, valid_window);
}

bool TOTP::verify(std::string const& key, size_t valid_window) const
{
	return verify(key, time(NULL), valid_window);
}

bool TOTP::verify(uint64_t key, size_t valid_window) const
{
	return verify(key, time(NULL), valid_window);
}

unsigned int TOTP::valid_until(uint64_t for_time, size_t valid_window) const
{
	return (for_time / m_interval + 1 + valid_window) * m_interval;
}

unsigned int TOTP::seconds_to_next_code(uint64_t for_time) const
{
	return m_interval - for_time % m_interval;
}

unsigned int TOTP::seconds_to_next_code() const
{
	return seconds_to_next_code(time(NULL));	
}

int TOTP::timecode(uint64_t for_time) const
{
	return for_time / m_interval;
}

std::string TOTP::build_uri() const
{
	return OTP::build_uri("totp", {{"period", std::to_string(m_interval)}});
}

std::ostream& TOTP::print(std::ostream& os) const
{
	os << "type: TOTP" << std::endl;
	OTP::print(os);
	os << "interval: " << m_interval << std::endl;

	return os;
}

std::ostream& operator<<(std::ostream& os, TOTP const& obj)
{
	obj.print(os);

	return os;
}

// ================================
// HOTP
// ================================

HOTP::HOTP(std::string const& base32_secret, std::string const& algo, size_t digits)
:HOTP(base32_secret, otp_algorithm_map.at(algo).bits, otp_algorithm_map.at(algo).algo, otp_algorithm_map.at(algo).name, digits)
{
}

HOTP::HOTP(std::string const& base32_secret, size_t bits, OTP_algorithm_ptr algo, std::string const& digest_algo_name, size_t digits)
: OTP(base32_secret, bits, algo, digest_algo_name, digits)
, m_counter(0)
{
	m_method = OTP_type::HOTP;
}

HOTP::HOTP(HOTP&& other)
: OTP(std::move(other)) 
{
	*this = std::move(other);
}

HOTP& HOTP::operator=(HOTP&& other)
{
	OTP::operator=(std::move(other));

	return *this;
}

OTP_ptr HOTP::create(OTP_URI const& uri)
{
	auto otp = std::make_shared<HOTP>(uri.get_secret(), uri.get_algorithm(), uri.get_digits());

	otp->set_issuer(uri.get_issuer());
	otp->set_account(uri.get_account());
	otp->set_counter(uri.get_counter());

	return otp;
}

void HOTP::set_counter(size_t value)
{
	m_counter = value;
}

size_t HOTP::get_counter() const
{
	return m_counter;
}

bool HOTP::compare(std::string const& key) const
{
	return (key == code_at(m_counter));
}

bool HOTP::compare(uint64_t key) const
{
	return compare(std::to_string(key));
}

std::string HOTP::code() const
{
	return generate(m_counter);
}

std::string HOTP::code_at(size_t counter) const
{
	return generate(counter);
}

bool HOTP::verify(std::string const& key) const
{
	return compare(key);
}

bool HOTP::verify(uint64_t key) const
{
	return compare(key);
}

std::string HOTP::build_uri() const
{
	return OTP::build_uri("hotp", {{"counter", std::to_string(m_counter)}});
}

std::ostream& HOTP::print(std::ostream& os) const
{
	os << "type: HOTP" << std::endl;
	OTP::print(os);
	os << "counter: " << m_counter << std::endl;

	return os;
}

std::ostream& operator<<(std::ostream& os, HOTP const& obj)
{
	obj.print(os);

	return os;
}

}
