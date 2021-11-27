/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include <iomanip>
#include <string>
#include <vector>

// This is not a generic URI class. (It may have been derived from one, but
// looked a bit overkill to use a full solution.)
//
// URI format: https://datatracker.ietf.org/doc/html/rfc3986
//
//	 otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
//
//	 - scheme: otpauth
//   - authority: totp/hotp
//            - called as 'type'
//   - path: label = [issuer:]account
//            - issuer optional, if present here and among parameters, it must be equal
//            - the `:` may be in urlencoded format (%3A)
//            - some implementations allow "account" to be empty
//   - query: parameters
//            - Secret (required, base32 format)
//            - Issuer (recommended, default empty string)
//            - Algorithm (optional, default: SHA-1)
//            - Digits (optional, default: 6)
//            - Counter (required for hotp)
//            - Period (optional, default: 30)
//

namespace cotp
{

// encodes given string into url-safe data
std::string urlencode(std::string const& text);

// encodes given byte vector into url-safe data
std::string urlencode(std::vector<char> const& bytes);

// decodes url-safe data to string
// works for ascii only
std::string urldecode(std::string const& str);

class OTP_URI
{
	friend std::ostream& operator<<(std::ostream& os, OTP_URI const& obj);

	public:
		OTP_URI();
		OTP_URI(std::string const& uri);
		~OTP_URI() = default;
	    OTP_URI(const OTP_URI&) = default;                  // copy constructor
	    OTP_URI& operator=(const OTP_URI& other) = default; // assignment operator
	    OTP_URI(OTP_URI&& other) = default;                 // move constructor
	    OTP_URI& operator=(OTP_URI&& other) = default;      // move assignment operator

	    std::string const& get_type() const;
	    std::string const& get_account() const;
	    std::string const& get_secret() const;
	    std::string const& get_issuer() const;
	    std::string const& get_algorithm() const;
	    size_t get_digits() const;
	    size_t get_counter() const;
	    size_t get_period() const;

	    void set_type(std::string value);
	    void set_account(std::string value);
	    void set_secret(std::string value);
	    void set_issuer(std::string value);
	    void set_algorithm(std::string value);
	    void set_digits(size_t value);
	    void set_counter(size_t value);
	    void set_period(size_t value);

	    std::string get_uri() const;

	private:
		std::string m_type;
		std::string m_account;
		std::string m_secret;
		std::string m_issuer;
		std::string m_algorithm;
		size_t m_digits;
		size_t m_counter;
		size_t m_period;

		void parse(std::string const& uri);
};

}