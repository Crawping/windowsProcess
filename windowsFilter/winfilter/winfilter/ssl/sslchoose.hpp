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

#ifndef OPENVPN_SSL_SSLCHOOSE_H
#define OPENVPN_SSL_SSLCHOOSE_H

#ifdef USE_OPENSSL
#include <winfilter/openssl/crypto/api.hpp>
#include <winfilter/openssl/ssl/sslctx.hpp>
#include <winfilter/openssl/util/rand.hpp>
#endif

#ifdef USE_APPLE_SSL
#include <winfilter/applecrypto/crypto/api.hpp>
#include <winfilter/applecrypto/ssl/sslctx.hpp>
#include <winfilter/applecrypto/util/rand.hpp>
#endif

#ifdef USE_MBEDTLS
#include <mbedtls/platform.h>
#include <mbedtls/debug.h>  // for debug_set_threshold
#include <winfilter/mbedtls/crypto/api.hpp>
#include <winfilter/mbedtls/ssl/sslctx.hpp>
#include <winfilter/mbedtls/util/rand.hpp>
#endif

#ifdef USE_MBEDTLS_APPLE_HYBRID
#include <winfilter/applecrypto/crypto/api.hpp>
#include <winfilter/mbedtls/ssl/sslctx.hpp>
#include <winfilter/mbedtls/util/rand.hpp>
#endif

namespace winfilter {
  namespace SSLLib {
#if defined(USE_MBEDTLS)
#define SSL_LIB_NAME "MbedTLS"
    typedef MbedTLSCryptoAPI CryptoAPI;
    typedef MbedTLSContext SSLAPI;
    typedef MbedTLSRandom RandomAPI;
#elif defined(USE_MBEDTLS_APPLE_HYBRID)
    // Uses Apple framework for CryptoAPI and MbedTLS for SSLAPI and RandomAPI
#define SSL_LIB_NAME "MbedTLSAppleHybrid"
    typedef AppleCryptoAPI CryptoAPI;
    typedef MbedTLSContext SSLAPI;
    typedef MbedTLSRandom RandomAPI;
#elif defined(USE_APPLE_SSL)
#define SSL_LIB_NAME "AppleSSL"
    typedef AppleCryptoAPI CryptoAPI;
    typedef AppleSSLContext SSLAPI;
    typedef AppleRandom RandomAPI;
#elif defined(USE_OPENSSL)
#define SSL_LIB_NAME "OpenSSL"
    typedef OpenSSLCryptoAPI CryptoAPI;
    typedef OpenSSLContext SSLAPI;
    typedef OpenSSLRandom RandomAPI;
#else
#error no SSL library defined
#endif
  }
}

#endif
