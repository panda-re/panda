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
**/

/**
 *  @Author Lok Yan
 */
#include "HelperFunctions.h"

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>

#include "bswap.h"

//#include "ErrorCodes.h"
#define NULL_POINTER_ERROR -1

using namespace std;

uint8_t hexCharToNibble(char c)
{
  if ( (c >= 'a') && (c <= 'f') )
  {
    return ((c - 'a') + 0xA);
  }
  if ( (c >= 'A') && (c <= 'F') )
  {
    return ((c - 'A') + 0xA);
  }
  if ( (c >= '0') && (c <= '9') )
  {
    return ((c - '0'));
  }
  return (0xFF);
}

int hexCharsToByte(uint8_t& h, char c1, char c2)
{
  uint8_t up = hexCharToNibble(c1);
  uint8_t down = hexCharToNibble(c2);
  if ( (up == 0xFF) || (down == 0xFF) )
  {
    return (-1);
  }
  h = ((up << 4) | (down));
  return (0);
}

// myHexStrToul needs to be able to take a 32 or 64 bit unsigned integer
// We defined a template so we only need to write the code once, and
// define these functions so C++ can do overload resolution in the template code
// since the existing bswap stuff is all macro magic
// and is undef'ed in the bswap header after used to define C functions
static void inline my_be_bswaps(uint32* p){
    be32_to_cpus(p);
}
static void inline my_be_bswaps(uint64* p){
    be64_to_cpus(p);
}
template<typename _ul> int myHexStrToul(_ul& ul, const string& str){
    uint8_t* pt = reinterpret_cast<uint8_t*>(&ul);
    size_t longlen = sizeof(_ul);
    int ret = myHexStrToBArray(pt, longlen, str);\
    my_be_bswaps(&ul);
    return ret;
}
template int myHexStrToul(uint32_t& ul, const string& str);
template int myHexStrToul(uint64_t& ul, const string& str);

/*
int myHexStrToul(uint32_t& ul, const char* str, char** end)
{
  bool bFoundZero = false;
  bool bHexFound = false;

  if (str == NULL)
  {
    return (-1);
  }

  //try the built in function first
  ul = strtoul(str, end, 16);
  //if ul is 0xFFFFFFFF or actually ULONG_MAX then we need to check errno for ERANGE
  if ( (ul == ULONG_MAX) && (errno == ERANGE) )
  {
    return (-1);
  }
  //if ul is 0, then it could either be because of an error
  // or because the value is truly zero, lets check the 0 condition
  if (ul == 0)
  {
    //if size is 0, then we know the problem
    if (str[0] == '\0')
    {
      return (-1);
    }

    //lets go through the string
    for (size_t i = 0; str[i] != '\0'; i++)
    {
      if ( !isspace(str[i]) )
      //if its not a whitespace character
      {
        //if the current character is a 0, then it can either be
        // the 0, or is part of 0x
        if (str[i] == '0')
        {
          //if its 0 and there is no character, then we are set
          if ( str[i + 1] == '\0' )
          {
            return (0);
          }
          //if its not the end of the string then see if its an x
          if ( (str[i+1] == 'x') || (str[i+1] == 'X') )
          {
            //if it is then if the header was found already (bHexFound)
            // then its an error
            //Another case for an error is if we found a zero before
            // which means this is more than 1 zero before the X
            if (bHexFound || bFoundZero)
            {
              return (-1);
            }
            i++; //skip the next character - this one
            //and mark that the header was found
            bHexFound = true;
          } //if the next value is NOT an x, then that means we found a true zero, the rest
          // of the values must be 0, otherwise we are in trouble
          else
          {
            bFoundZero = true;
          }
        }
        else
        {
          return (-1);
        }
      }
      else if (bHexFound || bFoundZero)
      {
        return (-1);
      }
    }
  }

  return (0);
}
*/



int myHexStrToBArray(uint8_t*& pul, size_t& count, const char* str)
{
  size_t beg = 0;
  size_t end = 0;
  size_t len = 0;
  bool bNeedNew = true;
  bool bFirst0 = false;

  if (str == NULL)
  {
    return (NULL_POINTER_ERROR);
  }

  if (pul != NULL)
  {
    if (count == 0)
    {
      return (-1);
    }

    bNeedNew = false;
  }

  //lets first find the beginning and end of the string - that is without whitespace
  for (int i = 0; str[i] != '\0'; i++)
  {
    if (isspace(str[i]))
    {
      continue;
    }
    if (str[i] == '0')
    {
      if ( (str[i+1] == 'x') || (str[i+1] == 'X') )
      {
        beg = i+2;
        break;
      }
    }
    beg = i;
    break;
  }

  //At this point, beg is either 0 - (could be all spaces) 
  //Or it is the first NON space character that is also not 0
  //Or it is the location right after 0x

  //now lets find the end
  for (end = beg; (str[end] != '\0') && (!isspace(str[end])); end++)
  {
    //if the nibble conversion didn't work then that means
    // we don't have a valid hex string
    if (hexCharToNibble(str[end]) == 0xFF)
    {
      return (-3);
    }  
  }

  //If beg == end, then that means we have all spaces so nothing to convert

  //now that we have the beginning and end, lets calculate the number of bytes we need
  // as well as the offset

  len = (end - beg) / 2; //2 characters per byte
  if ((end - beg) & 0x1)
  {
    //return (-3); // byte arrays should be of even length!
    //if the length is odd, then we add in a '0' in the beginning
    // unless count is less than the new length, in which case
    len++;
    bFirst0 = true;
  }

  if (len == 0)
  {
    //nothing to do
    return (-2);
  }

  //create the array if needed
  if (bNeedNew)
  {
    pul = new (uint8_t[len]);
    count = len;
  }
  //if count is less than len, then we don't prepend the 0 since
  // the space provided won't fit all of the characters anyways
  else if (count < len)
  {
    bFirst0 = false;
  }

  //now run through the array and get the values
  size_t i = beg;
  size_t j = 0;
  size_t num = 0;
  int ret = 0;

  if (bFirst0)
  {
    ret = hexCharsToByte(pul[j], '0', str[i]);
    j++;
    i++;
    num++;
  }

  if (ret != 0)
  {
    if (bNeedNew)
    {
      delete (pul);
      pul = NULL;
    }
    count = 0;
    return (-1);
  }

  while((i < end) && (num < count))
  {
    ret = hexCharsToByte(pul[j++], str[i], str[i+1]);

    if (ret != 0)
    {
      if (bNeedNew)
      {
        delete (pul);
        pul = NULL;
      }
      count = 0;
      return (-1);
    }

    i+=2;
    num++;
  }

  count = num;

  //if it ended, then we are done
  if (str[i] == '\0')
  {
    return (0);
  }

  //if it ended and the character is NOT a space character then we return 2
  for ( ; str[i] != '\0'; i++)
  {
    if (!isspace(str[i]))
    {
      return (2);
    }
  }

  //else return 1
  return (1);
}

int myHexStrToBArray(uint8_t*& pul, size_t& count, const string& str)
{
  return myHexStrToBArray(pul, count, str.c_str());
}
