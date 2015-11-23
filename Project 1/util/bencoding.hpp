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
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SBT_BENCODING_HPP
#define SBT_BENCODING_HPP

#include <vector>
#include <iostream>
#include <string>
#include <list>
#include <map>

#include "buffer.hpp"

namespace sbt {
namespace bencoding {

class Error : public std::runtime_error
{
public:
  explicit
  Error(const std::string& what)
    : std::runtime_error(what)
  {
  }
};

enum Type {
  TYPE_STRING = 1,
  TYPE_INTEGER = 2,
  TYPE_LIST = 3,
  TYPE_DICTIONARY = 4
};

class Base
{
public:
  Base(Type type);

  virtual
  ~Base();

  virtual void
  wireEncode(std::ostream& os) const = 0;

  virtual void
  wireDecode(std::istream& is) = 0;

  Type
  getType()
  {
    return m_type;
  }

  virtual void
  print(std::ostream& os, const std::string& indent) = 0;

private:
  Type m_type;
};

class String : public Base
{
public:
  String();

  explicit
  String(const std::string& value);

  String(const void* value, size_t size);

  virtual
  ~String();

  virtual void
  wireEncode(std::ostream& os) const;

  virtual void
  wireDecode(std::istream& is);

  const std::vector<uint8_t>&
  getValue()
  {
    return m_value;
  }

  const uint8_t*
  value()
  {
    if (m_value.empty())
      return 0;
    else
      return &m_value.front();
  }

  size_t
  size()
  {
    return m_value.size();
  }

  std::string
  toString();

  void
  print(std::ostream& os, const std::string& indent);

private:
  std::vector<uint8_t> m_value;
};

class Integer : public Base
{
public:
  Integer();

  explicit
  Integer(int64_t value);

  virtual
  ~Integer();

  virtual void
  wireEncode(std::ostream& os) const;

  virtual void
  wireDecode(std::istream& is);

  int64_t
  getValue()
  {
    return m_value;
  }

  void
  print(std::ostream& os, const std::string& indent);

private:
  int64_t m_value;
};

class List : public Base
{
public:
  typedef std::list<std::shared_ptr<Base>>::iterator iterator;
  typedef std::list<std::shared_ptr<Base>>::const_iterator const_iterator;

public:
  List();

  virtual
  ~List();

  virtual void
  wireEncode(std::ostream& os) const;

  virtual void
  wireDecode(std::istream& is);

  void
  append(std::shared_ptr<Base> item);

  const std::list<std::shared_ptr<Base>>&
  getList() const
  {
    return m_list;
  }

  iterator
  begin();

  iterator
  end();

  const_iterator
  begin() const;

  const_iterator
  end() const;

  void
  print(std::ostream& os, const std::string& indent);

private:
  std::list<std::shared_ptr<Base>> m_list;
};

class Dictionary : public Base
{
public:
  typedef std::map<std::string, std::shared_ptr<Base>>::iterator iterator;
  typedef std::map<std::string, std::shared_ptr<Base>>::const_iterator const_iterator;

public:
  Dictionary();

  virtual
  ~Dictionary();

  virtual void
  wireEncode(std::ostream& os) const;

  virtual void
  wireDecode(std::istream& is);

  void
  insert(const std::string& key, std::shared_ptr<Base> value);

  void
  erase(const std::string& key);

  std::shared_ptr<Base>
  get(const std::string& key) const;

  iterator
  begin();

  iterator
  end();

  const_iterator
  begin() const;

  const_iterator
  end() const;

  void
  print(std::ostream& os, const std::string& indent);

private:
  std::map<std::string, std::shared_ptr<Base>> m_map;
};

} // bencoding
} // sbt

#endif // SBT_BENCODING_HPP
