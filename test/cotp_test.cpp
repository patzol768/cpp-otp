
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <ctime>	// time
#include <cstring>	// strlen

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "cotp/cotp.hpp"
#include "cotp/qr_code.hpp"
#include "cotp/otp_factory.hpp"
#include "cotp/otp_uri.hpp"

using namespace std;

int main(int argc, char** argv) {
	cout << "run" << endl;

	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////
	
	const int INTERVAL	= 30;
	const int DIGITS	= 6;
	
	// Base32 secret to utilize
//	std::string BASE32_SECRET = "JBSWY3DPEHPK3PXP";
	std::string BASE32_SECRET = "THISISASECRET345";

	auto totp = cotp::TOTP(BASE32_SECRET, "SHA1", DIGITS, INTERVAL);
	auto hotp = cotp::HOTP(BASE32_SECRET, "SHA1", DIGITS);

	cout << "\\\\ totp tdata \\\\"		<< endl;
	cout << totp;
	cout << "code: " << totp.code() << endl;
	cout << "remaining seconds: " << totp.seconds_to_next_code() << endl;
	cout << "// totp tdata //"			<< endl << endl;
	
	cout << "\\\\ hotp hdata \\\\"		<< endl;
	cout << hotp;
	cout << "// hotp hdata //"			<< endl << endl;
	
	cout << "Current Time: `" << time(NULL) << "`" << endl;
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	totp.set_account("someone@example.com");
	totp.set_issuer("ACME INC");
	auto uri = totp.build_uri();
	cout << "TOTP URI: `" << uri << "`" << endl << endl;
	
	hotp.set_account("Árvíztűrő Tükörfúrógép");
	hotp.set_issuer("A Hungarian Entity");
	hotp.set_counter(52);
	uri = hotp.build_uri();
	cout << "HOTP URI: `" << uri << "`" << endl << endl;
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	// Seed random generator
	const int base32_len = 16;
	
	// Generate random base32
	auto base32_new_secret = cotp::OTP::random_base32(base32_len);
	cout << "Generated BASE32 Secret: `" << base32_new_secret << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// TOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for a time block
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load totp key into tcode
	//   3. Check for error
	//   4. Free data
	
	// TOTP now
	auto totp_code_now = totp.code();
	cout << "TOTP Generated: `" << totp_code_now << "`" << endl;
	
	
	// TOTP at
	auto totp_code_at = totp.code_at(1, 0);
	cout << "TOTP Generated: `" << totp_code_at << "`" << endl;
	
	// Do a verification for a hardcoded code
	
	// Won't succeed, this code is for a timeblock far into the past
	auto totp_verify_1 = totp.verify(576203, time(NULL), 4);
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	auto totp_verify_2 = totp.verify(282760, 0, 4);

	cout << "TOTP Verification 1: `" << (totp_verify_1 ? "true" : "false") << "`" << endl;
	cout << "TOTP Verification 2: `" << (totp_verify_2 ? "true" : "false") << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	auto hotp_code_at = hotp.code_at(1);
	cout << "HOTP Generated at 1: `" << hotp_code_at << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	hotp.set_counter(1);
	bool hotp_verify_1 = hotp.verify(996554);
	cout << "HOTP Verification 1: `" << (hotp_verify_1 ? "true" : "false") << "`" << endl;


	////////////////////////////////////////////////////////////////
	// RFC 6238 samples                                           //
	////////////////////////////////////////////////////////////////

	const string RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 encode of "12345678901234567890"
	const string RFC_SECRET_32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="; // base32 encode of "12345678901234567890123456789012"
	const string RFC_SECRET_64 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=="; // base32 encode of "1234567890123456789012345678901234567890123456789012345678901234"

	auto totp_8_sha1 = cotp::TOTP(RFC_SECRET, "SHA1", 8, 30);
	auto totp_8_sha256 = cotp::TOTP(RFC_SECRET_32, "SHA256", 8, 30);
	auto totp_8_sha512 = cotp::TOTP(RFC_SECRET_64, "SHA512", 8, 30);

	cout << "\\\\ rfc6238 samples \\\\"	 << endl;

	cout << "TOTP 8 SHA1   Generated at          59: `" << totp_8_sha1.code_at(59, 0) << "`" << endl;
	cout << "TOTP 8 SHA1   Generated at  1111111109: `" << totp_8_sha1.code_at(1111111109, 0) << "`" << endl;
	cout << "TOTP 8 SHA1   Generated at  1111111111: `" << totp_8_sha1.code_at(1111111111, 0) << "`" << endl;
	cout << "TOTP 8 SHA1   Generated at  1234567890: `" << totp_8_sha1.code_at(1234567890, 0) << "`" << endl;
	cout << "TOTP 8 SHA1   Generated at  2000000000: `" << totp_8_sha1.code_at(2000000000, 0) << "`" << endl;
	cout << "TOTP 8 SHA1   Generated at 20000000000: `" << totp_8_sha1.code_at(20000000000, 0) << "`" << endl;

	cout << "TOTP 8 SHA1   Verification          59: `" << (totp_8_sha1.verify(94287082, 59, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA1   Verification  1111111109: `" << (totp_8_sha1.verify( 7081804, 1111111109, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA1   Verification  1111111111: `" << (totp_8_sha1.verify(14050471, 1111111111, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA1   Verification  1234567890: `" << (totp_8_sha1.verify(89005924, 1234567890, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA1   Verification  2000000000: `" << (totp_8_sha1.verify(69279037, 2000000000, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA1   Verification 20000000000: `" << (totp_8_sha1.verify(65353130, 20000000000, 0) ? "true" : "false") << "`" << endl;

	cout << "TOTP 8 SHA256 Generated at          59: `" << totp_8_sha256.code_at(59, 0) << "`" << endl;
	cout << "TOTP 8 SHA256 Generated at  1111111109: `" << totp_8_sha256.code_at(1111111109, 0) << "`" << endl;
	cout << "TOTP 8 SHA256 Generated at  1111111111: `" << totp_8_sha256.code_at(1111111111, 0) << "`" << endl;
	cout << "TOTP 8 SHA256 Generated at  1234567890: `" << totp_8_sha256.code_at(1234567890, 0) << "`" << endl;
	cout << "TOTP 8 SHA256 Generated at  2000000000: `" << totp_8_sha256.code_at(2000000000, 0) << "`" << endl;
	cout << "TOTP 8 SHA256 Generated at 20000000000: `" << totp_8_sha256.code_at(20000000000, 0) << "`" << endl;

	cout << "TOTP 8 SHA256 Verification          59: `" << (totp_8_sha256.verify(46119246, 59, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA256 Verification  1111111109: `" << (totp_8_sha256.verify(68084774, 1111111109, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA256 Verification  1111111111: `" << (totp_8_sha256.verify(67062674, 1111111111, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA256 Verification  1234567890: `" << (totp_8_sha256.verify(91819424, 1234567890, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA256 Verification  2000000000: `" << (totp_8_sha256.verify(90698825, 2000000000, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA256 Verification 20000000000: `" << (totp_8_sha256.verify(77737706, 20000000000, 0) ? "true" : "false") << "`" << endl;

	cout << "TOTP 8 SHA512 Generated at          59: `" << totp_8_sha512.code_at(59, 0) << "`" << endl;
	cout << "TOTP 8 SHA512 Generated at  1111111109: `" << totp_8_sha512.code_at(1111111109, 0) << "`" << endl;
	cout << "TOTP 8 SHA512 Generated at  1111111111: `" << totp_8_sha512.code_at(1111111111, 0) << "`" << endl;
	cout << "TOTP 8 SHA512 Generated at  1234567890: `" << totp_8_sha512.code_at(1234567890, 0) << "`" << endl;
	cout << "TOTP 8 SHA512 Generated at  2000000000: `" << totp_8_sha512.code_at(2000000000, 0) << "`" << endl;
	cout << "TOTP 8 SHA512 Generated at 20000000000: `" << totp_8_sha512.code_at(20000000000, 0) << "`" << endl;

	cout << "TOTP 8 SHA512 Verification          59: `" << (totp_8_sha512.verify(90693936, 59, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA512 Verification  1111111109: `" << (totp_8_sha512.verify(25091201, 1111111109, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA512 Verification  1111111111: `" << (totp_8_sha512.verify(99943326, 1111111111, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA512 Verification  1234567890: `" << (totp_8_sha512.verify(93441116, 1234567890, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA512 Verification  2000000000: `" << (totp_8_sha512.verify(38618901, 2000000000, 0) ? "true" : "false") << "`" << endl;
	cout << "TOTP 8 SHA512 Verification 20000000000: `" << (totp_8_sha512.verify(47863826, 20000000000, 0) ? "true" : "false") << "`" << endl;

	cout << endl;

	cout << "\\\\ https://blog.dataforce.org.uk/2019/03/fun-with-totp-codes/ \\\\" << endl;

	const string FUN_SECRET = "LJZC6S3XHFHHMMDXNBJC4LDBJYZCMU35";

	auto totp_6_sha1 = cotp::TOTP(FUN_SECRET, "SHA1", 6, 30);
	auto totp_6_sha256 = cotp::TOTP(FUN_SECRET, "SHA256", 6, 30);
	auto totp_6_sha512 = cotp::TOTP(FUN_SECRET, "SHA512", 6, 30);

	cout << "TOTP 6 SHA1   Generated at block 51793295: `" << totp_6_sha1.code_at(0, 51793295) << "`" << endl;
	cout << "TOTP 6 SHA256 Generated at block 51793295: `" << totp_6_sha256.code_at(0, 51793295) << "`" << endl;
	cout << "TOTP 6 SHA512 Generated at block 51793295: `" << totp_6_sha512.code_at(0, 51793295) << "`" << endl;

	cout << endl;

	const string NOW_SECRET = "SECRETCODE";

	auto time_now = time(nullptr);

	auto totp_now_sha1 = cotp::TOTP(NOW_SECRET, "SHA1", 6, 30);
	totp_now_sha1.set_issuer("SECRETCODE - SHA1");
	totp_now_sha1.set_account("SHA1");
	cout << "uri: " << totp_now_sha1.build_uri() << endl;

	for(int i = -9; i <= 9; i++)
	{
		cout << "TOTP " << std::setw(2) << i << " SHA1   Generated at         now: `" << totp_now_sha1.code_at(time_now, i) << "`" << endl;
	}

	cout << endl;

	auto totp_now_sha256 = cotp::TOTP(NOW_SECRET, "SHA256", 6, 30);
	totp_now_sha256.set_issuer("SECRETCODE - SHA256");
	totp_now_sha256.set_account("SHA256");
	cout << "uri: " << totp_now_sha256.build_uri() << endl;

	for(int i = -9; i <= 9; i++)
	{
		cout << "TOTP " << std::setw(2) << i << " SHA256 Generated at         now: `" << totp_now_sha256.code_at(time_now, i) << "`" << endl;
	}

	cout << endl;

	auto totp_now_sha512 = cotp::TOTP(NOW_SECRET, "SHA512", 6, 30);
	totp_now_sha512.set_issuer("SECRETCODE - SHA512");
	totp_now_sha512.set_account("SHA512");
	cout << "uri: " << totp_now_sha512.build_uri() << endl;

	for(int i = -9; i <= 9; i++)
	{
		cout << "TOTP " << std::setw(2) << i << " SHA512 Generated at         now: `" << totp_now_sha512.code_at(time_now, i) << "`" << endl;
	}

	cout << endl;

	cout << "\\\\ https://www.nongnu.org/oath-toolkit/man-oathtool.html \\\\" << endl;

	const string OATH_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

	auto totp_oath_sha1 = cotp::TOTP(OATH_SECRET, "SHA1", 8, 30);
	auto hotp_oath_sha1 = cotp::HOTP(OATH_SECRET, "SHA1", 6);

	cout << "TOTP O SHA1   Generated at  2000000000: `" << totp_oath_sha1.code_at(2000000000, 0) << "`" << endl;

	for(int i = 0; i <= 9; i++)
	{
		cout << "HOTP Generated at " << i << ": `" << hotp_oath_sha1.code_at(i) << "`" << endl;
	}

	////////////////////////////////////////////////////////////////
	// QR code example                                            //
	////////////////////////////////////////////////////////////////

	ofstream svg_file;
	std::string svg_fn;

	cotp::QR_code totp_qr;
	totp_qr.set_content(totp);
	auto totp_svg = totp_qr.get_svg();
	svg_fn = "totp.svg";
	cout << "TOTP SVG file: " << svg_fn << endl << endl;
	svg_file.open(svg_fn);
	svg_file << totp_svg;
	svg_file.close();


	hotp.set_counter(52);	// just to be the same as the above printied uri
	cotp::QR_code hotp_qr;
	hotp_qr.set_content(hotp);
	cotp::QR_decoration decoration = { R"DECO(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="%viewbox%" stroke="none">
	<g transform="scale(%scale%)">
		<style>.caption { font: bold 190px sans-serif; fill: white; }</style>
		<rect x="0" y="0" width="1144" height="1332" rx="50" fill="#444444"/>
		<text x="90" y="204" class="caption">SCAN ME</text>
		<rect x="72" y="264" width="1000" height="1000" fill="#FFFFFF"/>
	</g>
	<g transform="translate(%translate%)">
		%qr_code%
	</g>
</svg>)DECO",
	1144,
	1332,
	72,
	264
};
	hotp_qr.set_decoration(decoration);
	auto hotp_svg = hotp_qr.get_svg();
	svg_fn = "hotp.svg";
	cout << "HOTP SVG file: " << svg_fn << endl << endl;
	svg_file.open(svg_fn);
	svg_file << hotp_svg;
	svg_file.close();

	totp_qr.set_content(totp_now_sha1);
	svg_fn = "totp_sha1.svg";
	cout << "TOTP SHA1 file: " << svg_fn << endl << endl;
	svg_file.open(svg_fn);
	svg_file << totp_qr.get_svg();
	svg_file.close();

	totp_qr.set_content(totp_now_sha256);
	svg_fn = "totp_sha256.svg";
	cout << "TOTP SHA256 file: " << svg_fn << endl << endl;
	svg_file.open(svg_fn);
	svg_file << totp_qr.get_svg();
	svg_file.close();

	totp_qr.set_content(totp_now_sha512);
	svg_fn = "totp_sha512.svg";
	cout << "TOTP SHA512 file: " << svg_fn << endl << endl;
	svg_file.open(svg_fn);
	svg_file << totp_qr.get_svg();
	svg_file.close();

	////////////////////////////////////////////////////////////////
	// Reverse URI                                                //
	////////////////////////////////////////////////////////////////

	std::string otp_uri_string = "otpauth://totp/account%40example.com:name1?secret=THISISASECRET345&issuer=account%40example.com&algorithm=SHA1&digits=6&period=30";
	cotp::OTP_URI otp_uri(otp_uri_string);

	cout << otp_uri << endl << endl;

	////////////////////////////////////////////////////////////////
	// Factory                                                    //
	////////////////////////////////////////////////////////////////

	auto otp_from_uri = cotp::OTP_factory::get_instance().create(otp_uri_string);

	cout << "URI: " << otp_uri_string << endl;
	cout << "OTP from URI: " << endl; otp_from_uri->print(cout); cout << endl;
	cout << "OTP from URI code   : `" << otp_from_uri->code() << "`" << endl;
	cout << "Original TOTP'd code: `" << totp.code() << "`" << endl;

	// to check that codes are the same (should be)
	auto totp_verify_3 = totp.verify(otp_from_uri->code(), 4);
	cout << "Verification: `" << (totp_verify_3 ? "true" : "false") << "`" << endl;

	return 0;
}
