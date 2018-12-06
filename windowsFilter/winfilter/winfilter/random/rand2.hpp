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

#pragma once

#include <utility>

#include <winfilter/random/randapi.hpp>

namespace winfilter {

  // By convention, rng is crypto-strength while prng is
  // not.  Be sure to always call RandomAPI::assert_crypto()
  // before using an rng for crypto purposes, to verify that
  // it is crypto-capable.
  struct Rand2
  {
    Rand2() {}

    Rand2(RandomAPI::Ptr rng_arg,
	  RandomAPI::Ptr prng_arg)
      : rng(std::move(rng_arg)),
	prng(std::move(prng_arg))
    {
    }

    Rand2(RandomAPI::Ptr rng_arg)
      : rng(std::move(rng_arg)),
	prng(std::move(rng_arg))
    {
    }

    RandomAPI::Ptr rng;
    RandomAPI::Ptr prng;
  };

}
