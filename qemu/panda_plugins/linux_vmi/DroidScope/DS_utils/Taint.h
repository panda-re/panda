/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file Class for a data structure that holds tainting information
 * @Author Lok Yan
 */

#ifndef TAINT_H
#define TAINT_H

#include <set>
//#include <map>
#include <tr1/unordered_map>
#include <inttypes.h>

template <class T>
class Taint
{

public:
  typedef std::set< T > taints_set_t;
  //typedef std::map< uint32_t, taints_set_t > taint_t;
  typedef std::tr1::unordered_map< uint32_t, taints_set_t > taint_t;
  //define the typenames for the iterators
  typedef typename taint_t::const_iterator const_iterator;
  typedef typename taint_t::iterator iterator;
  typedef typename std::set<T>::const_iterator const_set_iterator;
  typedef typename std::set<T>::iterator set_iterator;

  Taint() {}
  void addTaint(uint32_t addr, T taint);
  void addTaints(uint32_t addr, const std::set< T >& taint);
  void removeTaint(uint32_t addr, T taint);
  void removeTaints(uint32_t addr, const std::set< T >& taint);
  void andTaints(uint32_t addr, uint32_t addr2);
  void orTaints(uint32_t addr, uint32_t addr2);

  const_iterator find(uint32_t addr) const { return (mTaints.find(addr)); }
  taints_set_t& operator [](uint32_t addr) { return (mTaints[addr]); }
  const_iterator begin() const { return (mTaints.begin()); }
  iterator begin() { return (mTaints.begin()); }
  const_iterator end() const { return (mTaints.end()); }
  iterator end() { return (mTaints.end()); }

  static void andTaints(taints_set_t& t1, const taints_set_t& t2);
  static void orTaints(taints_set_t& t1, const taints_set_t& t2);
private:
  taint_t mTaints;

};

template <class T>
void Taint<T>::addTaint(uint32_t addr, T taint)
{
  mTaints[addr].insert(taint);
}

template <class T>
void Taint<T>::addTaints(uint32_t addr, const std::set<T>& taints)
{
  std::set< T >& tRef = mTaints[addr];

  const_set_iterator it;
  for (it = taints.begin(); it != taints.end(); it++)
  {
    tRef.insert(*it);
  }
}

template <class T>
void Taint<T>::removeTaint( uint32_t addr, T taint)
{
  iterator it;
  it = mTaints.find(addr);
  if (it != mTaints.end())
  {
    it->second.erase(taint);
  }
}

template <class T>
void Taint<T>::removeTaints(uint32_t addr, const std::set<T>& taints)
{
  iterator it;
  it = mTaints.find(addr);
  if (it != mTaints.end())
  {
    const_set_iterator cit;
    for (cit = taints.begin(); cit = taints.end(); cit++)
    {
      it->second.erase(*cit);
    }
  }
}

template <class T>
void Taint<T>::andTaints(uint32_t addr, uint32_t addr2)
{
  if (addr == addr2)
  {
    return;
  }

  iterator it1;
  iterator it2;
  it1 = mTaints.find(addr);
  it2 = mTaints.find(addr2);
  if (it1 == mTaints.end())
  { //nothing to do
    return;
  }

  if (it2 == mTaints.end())
  {
    it1->second.clear();
    return;
  }

  andTaints(it1->second, it2->second);
  /*
  //in this case we need to go through the taints of the first
  // and second and create a temporary list that we can swap
  std::set< T > temp;
  set_iterator it3;
  set_iterator it4;
  for (it3 = it1->second.begin(); it3 != it1->second.end(); it3++)
  {
    it4 = it2->second.find(*it3);
    //if it exists
    if (it4 != it2->second.end())
    {
      temp.insert(*it4);
    }
  }

  it1->second.swap(temp);
  */
}

template <class T>
void Taint<T>::orTaints(uint32_t addr, uint32_t addr2)
{
  if (addr == addr2)
  {
    return;
  }

  iterator it = mTaints.find(addr2);
  if (it != mTaints.end())
  {
    addTaints(addr, it->second);
  }
}

//STATIC METHODS
template <class T>
void Taint<T>::andTaints(taints_set_t& t1, const taints_set_t& t2)
{
  if ((&t1 == &t2) || (t1 == t2))
  {
    return;
  }

  std::set< T > temp;
  set_iterator it;
  set_iterator it2;

  for (it = t1.begin(); it != t1.end(); it++)
  {
    it2 = t2.find(*it);
    //if it exists
    if (it2 != t2.end())
    {
      temp.insert(*it2);
    }
  }

  t1.swap(temp);
}

template <class T>
void Taint<T>::orTaints(taints_set_t& t1, const taints_set_t& t2)
{
  if ((&t1 == &t2) || (t1 == t2))
  {
    return;
  }

  const_set_iterator it;
  for (it = t2.begin(); it != t2.end(); ++it)
  {
    t1.insert(*it);
  }
}

#endif//TAINT_H
