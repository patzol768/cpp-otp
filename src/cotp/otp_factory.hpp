/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include "cotp/cotp.hpp"
#include "cotp/otp_uri.hpp"

#include <functional>
#include <string>

namespace cotp
{

typedef std::function<OTP_ptr(OTP_URI const& uri)> OTP_creator_function;

class OTP_factory
{
    public:
	    static OTP_factory& get_instance();

	    void register_named(std::string const& name, OTP_creator_function const& creator);

	    OTP_creator_function const& get_creator(std::string const& name) const;
	    OTP_ptr create(std::string const& uri) const;

    private:
	    OTP_factory();
	    OTP_factory(const OTP_factory&) = delete;                  // copy constructor
	    OTP_factory& operator=(const OTP_factory& other) = delete; // assignment operator
	    OTP_factory(OTP_factory&& other) = delete;                 // move constructor
	    OTP_factory& operator=(OTP_factory&& other) = delete;      // move assignment operator

	    std::map<std::string, OTP_creator_function> m_creators;

};

}
