//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_OPENSSL_CRYPTO_API_H
#define OPENVPN_OPENSSL_CRYPTO_API_H

#include <winfilter/openssl/crypto/cipher.hpp>
#include <winfilter/openssl/crypto/ciphergcm.hpp>
#include <winfilter/openssl/crypto/digest.hpp>
#include <winfilter/openssl/crypto/hmac.hpp>

namespace winfilter {

  // type container for OpenSSL Crypto-level API
  struct OpenSSLCryptoAPI {
    // cipher
    typedef OpenSSLCrypto::CipherContext CipherContext;
    typedef OpenSSLCrypto::CipherContextGCM CipherContextGCM;

    // digest
    typedef OpenSSLCrypto::DigestContext DigestContext;

    // HMAC
    typedef OpenSSLCrypto::HMACContext HMACContext;
  };
}

#endif
