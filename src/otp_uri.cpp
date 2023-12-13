/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#include "cotp/otp_uri.hpp"

#include <cstdint>
#include <exception>
#include <map>
#include <regex>
#include <stdexcept>

namespace cotp
{

// ================================
// tools
// ================================

static uint8_t h2d(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}

	if (c >= 'a' && c <= 'f')
	{
		return c + 10 - 'a';
	}

	if (c >= 'A' && c <= 'F')
	{
		return c + 10 - 'A';
	}

	throw std::logic_error("non-hex char");
}

static std::map<std::string, std::string> get_params(std::string const& params)
{
	std::map<std::string, std::string> param_map;

	if (params.empty())
	{
		return param_map;
	}

	size_t p = 0;
	auto params_size = params.size();

	while(p < params_size)
	{
		std::string param;
		size_t at_in_params = params.find('&', p);
		if (at_in_params != std::string::npos)
		{
			param = params.substr(p, at_in_params - p);
		}
		else
		{
			param = params.substr(p);
		}

		size_t eqsign_in_param = param.find('=', p);
		if (eqsign_in_param != std::string::npos)
		{
			std::string key = param.substr(0, eqsign_in_param);
			std::string value = urldecode(param.substr(eqsign_in_param + 1));

			if (param_map.find(key) != param_map.end())
			{
				throw std::logic_error("ambiguous parameter");
			}

			param_map.insert({key, value});
		}

		p += param.size() + 1;
	}

	return param_map;
}

std::string urlencode(std::string const& text)
{
	std::vector<char> v(text.begin(), text.end());

	return urlencode(v);
}

std::string urlencode(std::vector<char> const& bytes)
{
	if (bytes.empty())
	{
		return "";
	}

	static const std::string to_test = "\"<>#%@{}|\\^~[]` ?&";

	std::ostringstream oss;

	for(auto const c : bytes)
	{
		if (c < 0x20 || to_test.find(c) != std::string::npos)	// 0x80 - 0xFF are negative values
		{
			oss << '%' << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << ((u_int)c&0xff);
		}
		else
		{
			oss << c;
		}
	}

	return oss.str();
}

std::string urldecode(std::string const& str)
{
	size_t p = 0;
	size_t str_size = str.size();
	std::string decoded;

	for(size_t p = 0; p < str_size; ++p)
	{
		auto c = str[p];
		
		if (c != '%')
		{
			decoded += c;
		}
		else
		{
			if (p + 2 < str_size)
			{
				char chr = h2d(str[p + 1]) << 4 | h2d(str[p + 2]);

				decoded += chr;
			}
			else
			{
				throw std::logic_error("premature end");
			}

			p += 2;
		}
	}

	return decoded;
}

// ================================
// OTP_URI
// ================================

OTP_URI::OTP_URI()
: m_issuer()
, m_algorithm("SHA1")
, m_digits(6)
, m_counter(0)
, m_period(30)
{
}

OTP_URI::OTP_URI(std::string const& uri)
: m_issuer()
, m_algorithm("SHA1")
, m_digits(6)
, m_counter(0)
, m_period(30)
{
	parse(uri);
}

std::string const& OTP_URI::get_type() const
{
	return m_type;
}

std::string const& OTP_URI::get_account() const
{
	return m_account;
}

std::string const& OTP_URI::get_secret() const
{
	return m_secret;
}

std::string const& OTP_URI::get_issuer() const
{
	return m_issuer;
}

std::string const& OTP_URI::get_algorithm() const
{
	return m_algorithm;
}

size_t OTP_URI::get_digits() const
{
	return m_digits;
}

size_t OTP_URI::get_counter() const
{
	return m_counter;
}

size_t OTP_URI::get_period() const
{
	return m_period;
}

void OTP_URI::set_type(std::string value)
{
	m_type = value;
}

void OTP_URI::set_account(std::string value)
{
	m_account = value;
}

void OTP_URI::set_secret(std::string value)
{
	m_secret = value;
}

void OTP_URI::set_issuer(std::string value)
{
	m_issuer = value;
}

void OTP_URI::set_algorithm(std::string value)
{
	m_algorithm = value;
}

void OTP_URI::set_digits(size_t value)
{
	m_digits = value;
}

void OTP_URI::set_counter(size_t value)
{
	m_counter = value;
}

void OTP_URI::set_period(size_t value)
{
	m_period = value;
}

void OTP_URI::parse(std::string const& uri)
{
	static const std::regex pattern( "^otpauth:\\/\\/(totp|hotp)\\/([^\\?]*)\\?(.*)" );

	std::smatch match;

    if ( !regex_search( uri, match, pattern ) )
    {
    	throw std::logic_error("uri not match");
    }

    m_type = match[1];

    std::string label = urldecode(match[2]);

    auto colon_in_label = label.find(':');
    if (colon_in_label == std::string::npos)
    {
    	m_account = label;
    }
    else
    {
    	m_issuer = label.substr(0, colon_in_label);
    	m_account = label.substr(colon_in_label + 1);
    }

    auto params = get_params(match[3]);

    if (params.find("issuer") != params.end())
    {
    	std::string param_issuer = params.at("issuer");

    	if (!m_issuer.empty() && m_issuer != param_issuer)
    	{
    		throw std::logic_error("ambiguous issuer");
    	}
	
		m_issuer = param_issuer;
    }

    if (params.find("secret") == params.end())
    {
    	throw std::logic_error("secret missing");
    }

    m_secret = params.at("secret");

    if (params.find("algorithm") != params.end())
    {
    	m_algorithm = params.at("algorithm");
    }

    if (params.find("digits") != params.end())
    {
    	m_digits = std::stoul(params.at("digits"));
    }

    if (params.find("counter") != params.end())
    {
    	m_counter = std::stoull(params.at("counter"));
    }
    else
    {
    	if (m_type == "hotp")
    	{
    		throw std::logic_error("missing counter");
    	}
    }

    if (params.find("period") != params.end())
    {
    	m_period = std::stoul(params.at("period"));
    }
}

std::string OTP_URI::get_uri() const
{
	if (m_issuer.empty() || m_account.empty() || m_type.empty())
	{
		return "";
	}

	auto cissuer = urlencode(m_issuer);
	auto secret = urlencode(m_secret);
	auto digest = urlencode(m_algorithm);

	std::string args = "?secret=" + secret + "&issuer=" + cissuer + "&algorithm=" + digest + "&digits=" + std::to_string(m_digits);
	
	if (m_type == "hotp")
	{
		args += "&counter=" + std::to_string(m_counter);
	}

	if (m_type == "totp")
	{
		args += "&period=" + std::to_string(m_period);
	}
	
	std::string uri = "otpauth://" + m_type + "/" + cissuer + ":" + urlencode(m_account) + args;

	return uri;
}

std::ostream& operator<<(std::ostream& os, OTP_URI const& obj)
{
	os << "type: " << obj.m_type << std::endl;
	os << "account: " << obj.m_account << std::endl;
	os << "secret: " << obj.m_secret << std::endl;
	os << "issuer: " << obj.m_issuer << std::endl;
	os << "algorithm: " << obj.m_algorithm << std::endl;
	os << "digits: " << obj.m_digits << std::endl;
	os << "counter: " << obj.m_counter << std::endl;
	os << "period: " << obj.m_period << std::endl;

	return os;
}

}
