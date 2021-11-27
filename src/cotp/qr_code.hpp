/* TOTP / HOTP library
 *
 * See README.md
 * See LICENSE
 *
 * 2021 Z. Patocs
 *
 */

#pragma once

#include <memory>
#include <qrcodegen.hpp>
#include <string>

namespace cotp
{
struct QR_decoration
{
	std::string svg;	// SVG, with related parts replaced. See set_decoration()
	double width;		// Total width of the decoration svg
	double height;		// Total height of the decoration svg
	double x;			// Top left X position of the qr rectangle inside the svg
	double y;			// Top left Y position of the qr rectangle inside the svg
};

class QR_code
{
	public:
		QR_code();
		~QR_code() = default;
	    QR_code(const QR_code&) = default;                  // copy constructor
	    QR_code& operator=(const QR_code& other) = default; // assignment operator
	    QR_code(QR_code&& other) = default;                 // move constructor
	    QR_code& operator=(QR_code&& other) = default;      // move assignment operator

		template<typename T>
		void set_content(T const& obj)
		{
			std::string qr_string = obj.get_qr_string();

			set_content(qr_string);
		}

		void set_content(std::string const& value);
		void set_error_correction_level(qrcodegen::QrCode::Ecc value);

		// Size of the white border around the QR
		void set_border(size_t value);

		// Decoration is a prepared svg image, with an 1000x1000 pixel
		// rectangle to place the QR code into
		//
		// The following replacement would be made:
		//   %viewbox% with the scaled size
		//   %scale% with the scale
		//   %translate% with the scaled left upper corner of the rectangle
		//   %qr_code% with the qr code
		void set_decoration(QR_decoration const& value);

		// Sets decoration to the original (none)
		void clear_decoration();

		std::string get_content() const;
		qrcodegen::QrCode::Ecc get_error_correction_level() const;
		size_t get_border() const;

		// Create the QG in SVG format and return as a string
		std::string get_svg() const;

	private:
		static const QR_decoration default_decoration;

		std::string m_content;
		std::shared_ptr<qrcodegen::QrCode> m_qr;
		qrcodegen::QrCode::Ecc m_error_correction_level;
		size_t m_border;

		QR_decoration m_decoration;

		void replace(std::string& str, std::string const& what, std::string const& with) const;
};

}

