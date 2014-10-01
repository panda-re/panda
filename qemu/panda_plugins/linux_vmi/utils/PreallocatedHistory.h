/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**//*
 * PreallocatedHistory.h
 *
 *  Created on: Oct 14, 2011
 *      Author: lok
 */

#ifndef PREALLOCATEDHISTORY_H_
#define PREALLOCATEDHISTORY_H_

/**
 * @file Template class for storing a "history"
 * What is special about this is that it preallocates the elements and allows the user to obtain a reference
 *  to the top element.
 * I did this so that keeping a string history will have better performance since we can get a string reference
 *  and then read the string using the reference instead of reading the string from a file first, and then
 *  pushing it onto the stack, which would need an unnecessary copy
 * @Author Lok Yan
 */

/**
 * Uses a circular array
 */
template <class T>
class PreallocatedHistory
{
private:
  size_t maxLines; //maximum number of lines in the history
  size_t mBeg; //index of the first element
  size_t mEnd; //index of the last element
  size_t mSize; //number of lines in the history
  T empty;
  T* aElements; //a circular array of elements

  void initElements();

public:
  /**
   * Default constructor that sets history size to 10
   */
  PreallocatedHistory() : maxLines(10), mBeg(0), mEnd(0), mSize(0), aElements(NULL) { initElements(); }

  PreallocatedHistory(size_t max) : maxLines(max), mBeg(0), mEnd(0), mSize(0), aElements(NULL) { initElements(); }

  /**
   * Constructor for setting what is returned if history is empty
   * @param newEmpty
   */
  PreallocatedHistory(const T& newEmpty) : maxLines(10), empty(newEmpty), mBeg(0), mEnd(0), mSize(0), aElements(NULL) { initElements(); }

  PreallocatedHistory(size_t max, const T& newEmpty) : maxLines(max), empty(newEmpty), mBeg(0), mEnd(0), mSize(0), aElements(NULL)  { initElements(); }

  /**
   * Sets what to return if "empty"
   * @param newEmpty
   */
  void setEmpty(const T& newEmpty) { empty = newEmpty; }

  /**
   * @return True if the history is empty
   */
  bool isEmpty() const { return (mSize == 0); }

  /**
   * @return Current maximum stSize
   */
  size_t getMaxSize() const { return (maxLines); }

  /**
   * @return Number of items in the history
   */
  size_t size() const { return (mSize); }

  /**
   * Clears the history
   */
  void clear() { mSize = 0; }

  /**
   * Push a new item into the back of the history
   * @param s The new item to push in
   */
  void push(const T& s);

  /**
   * Gets the item at index i. Returns "empty" if i is outside of the boundaries
   * @param i The index
   * @return Const reference to the item.
   */
  const T& at(size_t i) const;

  /**
   * Gets a reference to the item, and automatically "push" it into the history
   * @return
   */
  T& getRefAndPush();

  /**
   * Truncates the history to the number of elements specified
   *
   */
  void truncate(size_t s);
};

template <class T>
void PreallocatedHistory<T>::initElements()
{
  if (aElements != NULL)
  {
    return;
  }

  aElements = new (T[maxLines]);
  //notice that I don't check whether aElements is NULL
  // I check these things during runtime anyways
}

template <class T>
void PreallocatedHistory<T>::push(const T& s)
{
  //to push, what we need to do is first check to see if the size is max -- this is very likely
  if (mSize == maxLines)
  {
    mBeg++; //increment begin -- this kills the first element
    mBeg = mBeg % maxLines; //this makes sure that mBeg is an index
  }
  else //note that we don't need to increment begin, since the array is not yet full, but we do need to increment the size
  {
    mSize++;
  }

  mEnd++; //increment mEnd -- same reasons
  mEnd = mEnd % maxLines;

  //now copy things over
  aElements[mEnd] = s;
}

template <class T>
const T& PreallocatedHistory<T>::at(size_t i) const
{
  if (i >= mSize)
  {
    return empty;
  }

  //else calculate the index
  i += mBeg;
  i = i % maxLines;

  return (aElements[i]);
}

template <class T>
T& PreallocatedHistory<T>::getRefAndPush() //basically, same as push, but get the reference for the new mEnd element
{
  //we can't call push, because there is nothing to push in, so just copied the code over here

  //to push, what we need to do is first check to see if the size is max -- this is very likely
  if (mSize == maxLines)
  {
    mBeg++; //increment begin -- this kills the first element
    mBeg = mBeg % maxLines; //this makes sure that mBeg is an index
  }
  else //note that we don't need to increment begin, since the array is not yet full, but we do need to increment the size
  {
    mSize++;
  }

  mEnd++; //increment mEnd -- same reasons
  mEnd = mEnd % maxLines;

  return (aElements[mEnd]);
}

#endif /* PREALLOCATEDHISTORY_H_ */
