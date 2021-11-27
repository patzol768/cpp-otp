/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#include "cotp/qr_code.hpp"

#include <memory>
#include <sstream>
#include <stdexcept>

namespace cotp
{
// empty decoration
//
	const QR_decoration QR_code::default_decoration = { R"DECO(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="%viewbox%" stroke="none">
	<rect width="100%" height="100%" fill="#FFFFFF"/>
	<g transform="translate(%translate%)">
		%qr_code%
	</g>
</svg>
)DECO",
	1000,
	1000,
	0,
	0
};

// decoration with "SCAN ME"
//
// 	const QR_decoration QR_code::default_decoration = { R"DECO(
// <?xml version="1.0" encoding="UTF-8"?>
// <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
// <svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="%viewbox%" stroke="none">
// 	<g transform="scale(%scale%)">
// 		<style>.caption { font: bold 190px sans-serif; fill: white; }</style>
// 		<rect x="0" y="0" width="1144" height="1332" rx="50" fill="#444444"/>
// 		<text x="90" y="204" class="caption">SCAN ME</text>
// 		<rect x="72" y="264" width="1000" height="1000" fill="#FFFFFF"/>
// 	</g>
// 	<g transform="translate(%translate%)">
// 		%qr_code%
// 	</g>
// </svg>)DECO",
// 	1144,
// 	1332,
// 	72,
// 	264
// };


	QR_code::QR_code()
	: m_qr(nullptr)
	, m_error_correction_level(qrcodegen::QrCode::Ecc::MEDIUM)
	, m_border(4)
	, m_decoration(default_decoration)
	{
	}

	void QR_code::set_content(std::string const& value)
	{
		m_content = value;
		m_qr = std::make_shared<qrcodegen::QrCode>(qrcodegen::QrCode::encodeText(m_content.c_str(), m_error_correction_level));
	}

	void QR_code::set_error_correction_level(qrcodegen::QrCode::Ecc value)
	{
		m_error_correction_level = value;
	}

	void QR_code::set_border(size_t value)
	{
		if (value >= 1024)	// could be higher, but be realistic
		{
			throw std::logic_error("border too big");
		}

		m_border = value;
	}

	std::string QR_code::get_content() const
	{
		return m_content;
	}

	qrcodegen::QrCode::Ecc QR_code::get_error_correction_level() const
	{
		return m_error_correction_level;
	}

	size_t QR_code::get_border() const
	{
		return m_border;
	}

	void QR_code::set_decoration(QR_decoration const& value)
	{
		m_decoration = value;
	}

	void QR_code::clear_decoration()
	{
		m_decoration = default_decoration;
	}

	std::string QR_code::get_svg() const
	{
		size_t qr_size = (m_qr != nullptr) ? m_qr->getSize() : 0;
		size_t qr_size_with_border = qr_size + 2 * m_border;

		double scale = (double)qr_size_with_border / 1000.0;

		std::string viewbox = "0 0 " + std::to_string(m_decoration.width * scale) + " " + std::to_string(m_decoration.height * scale);
		std::string scale_str = std::to_string(scale) + " " + std::to_string(scale);
		std::string translate = std::to_string(m_decoration.x * scale) + " " + std::to_string(m_decoration.y * scale);

		std::ostringstream sb;
		sb << "\t<path d=\"";
		for (int y = 0; y < qr_size; y++) {
			for (int x = 0; x < qr_size; x++) {
				if (m_qr->getModule(x, y)) {
					if (x != 0 || y != 0)
						sb << " ";
					sb << "M" << (x + m_border) << "," << (y + m_border) << "h1v1h-1z";
				}
			}
		}
		sb << "\" fill=\"#000000\"/>";
		std::string qr_code = sb.str();
		std::string svg = m_decoration.svg;

		replace(svg, "%viewbox%", viewbox);
		replace(svg, "%scale%", scale_str);
		replace(svg, "%translate%", translate);
		replace(svg, "%qr_code%", qr_code);

		return svg;
	}

	void QR_code::replace(std::string& str, std::string const& what, std::string const& with) const
	{
		auto pos = str.find(what);
        
        if (pos == std::string::npos)
        {
        	return;
        }

        str.replace(pos, what.size(), with);
	}
}
