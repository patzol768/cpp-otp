/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#include "cotp/otp_factory.hpp"

#include <stdexcept>

namespace cotp
{

OTP_factory::OTP_factory()
: m_creators()
{
}

OTP_factory& OTP_factory::get_instance()
{
    static std::unique_ptr<OTP_factory> m_instance(new OTP_factory);
    return *m_instance;
}

void OTP_factory::register_named(std::string const& name, OTP_creator_function const& creator)
{
    if (m_creators.find(name) != m_creators.end())
    {
        throw std::logic_error("factory: already registered");
    }

    m_creators.insert({name, creator});
}

OTP_creator_function const& OTP_factory::get_creator(std::string const& name) const
{
    if (m_creators.find(name) == m_creators.end())
    {
        throw std::logic_error("factory: creator not found");
    }

    return m_creators.at(name);
}

OTP_ptr OTP_factory::create(std::string const& uri) const
{
	cotp::OTP_URI otp_uri(uri);

    return get_creator(otp_uri.get_type())(otp_uri);
}

}
