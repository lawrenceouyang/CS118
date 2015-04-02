/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Alex Afanasyev <alexander.afanasyev@ucla.edu>
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef SBT_HTTP_REQUEST_HPP
#define SBT_HTTP_REQUEST_HPP

#include "http-headers.hpp"

namespace sbt {
/**
 * @brief Class to parse/create HTTP requests
 *
 *  HttpRequest objects are created from parsing a buffer containing a HTTP
 *  request. The request buffer consists of a request line followed by a number
 *  of headers. Request line fields such as method, protocol etc. are stored
 *  explicitly. Headers such as 'Content-Length' and their values are maintained
 *  in a linked list.
 *
 * Example:
 *      // command line parsing
 *      HttpRequest req;
 *      req.setHost("www.google.com");
 *      req.setPort(80);
 *      req.setMethod(HttpRequest::GET);
 *      req.setPath("/");
 *      req.setVersion("1.0");
 *      req.addHeader("Accept-Language", "en-US");
 *
 *      size_t reqLen = req.getTotalLength();
 *      char *buf = new char [reqLen];
 *
 *      req.formatRequest(buf);
 *      cout << buf;
 *
 *      delete [] buf;
 */
class HttpRequest : public HttpHeaders
{
public:
  enum MethodEnum
    {
      GET = 0,
      UNSUPPORTED = 1
    };

  /**
   * @brief Default constructor
   *
   * Example:
   * HttpRequest req;
   * req.setMethod(HttpRequest::GET);
   * req.setHost("www.google.com");
   * ...
   */
  HttpRequest();

  /**
   * @brief Parse HTTP header
   *
   * Example:
   * HttpRequest req;
   * const char *buf = "GET http://www.google.com:80/index.html/ HTTP/1.0\r\nContent-Length:"
   *                   " 80\r\nIf-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n\r\n";
   * req.Parse(buf);
   */
  const char*
  parseRequest(const char* buffer, size_t size);

  /**
   * @brief Get total length of the HTTP header
   *        (buffer size necessary to hold formatted HTTP request)
   */
  size_t
  getTotalLength() const;

  /**
   * @brief Format HTTP request
   *
   * Note that buffer size should be enough to hold the request
   * (e.g., obtained from GetTotalLength() call). Otherwise, anything can happen.
   *
   * @param buffer [out] Buffer that will hold formatted request
   * @returns Number of bytes actually written to the buffer
   */
  char*
  formatRequest(char* buffer) const;

  // Getters/Setters for HTTP request fields

  /**
   * @brief Get method of the HTTP request
   */
  MethodEnum
  getMethod() const;

  /**
   * @brief Set method of the HTTP request
   */
  void
  setMethod(MethodEnum method);

  // /**
  //  * @brief Set method of the HTTP request
  //  */
  // const std::string &
  // GetProtocol () const;

  // /**
  //  * @brief Set method of the HTTP request
  //  */
  // void
  // SetProtocol (const std::string &protocol);

  /**
   * @brief Get host of the HTTP request
   */
  const std::string&
  getHost() const;

  /**
   * @brief Set host of the HTTP request
   */
  void
  setHost(const std::string& host);

  /**
   * @brief Get port of the HTTP request
   */
  unsigned short
  getPort() const;

  /**
   * @brief Set port of the HTTP request
   */
  void
  setPort(unsigned short port);

  /**
   * @brief Get path of the HTTP request
   */
  const std::string&
  getPath() const;

  /**
   * @brief Set path of the HTTP request
   */
  void
  setPath(const std::string& path);

  /**
   * @brief Get version of the HTTP request
   */
  const std::string&
  getVersion() const;

  /**
   * @brief Set version of the HTTP request
   */
  void
  setVersion(const std::string& version);

private:
  MethodEnum  m_method;
  std::string m_host;
  unsigned short m_port;
  std::string m_path;
  std::string m_version;
};

} // namespace sbt

#endif // SBT_HTTP_REQUEST_HPP
