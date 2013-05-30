/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#ifndef _android_sms_h
#define _android_sms_h

#include <time.h>

/** MESSAGE TEXT
 **/
/* convert a quoted message text into a utf8 string. Note: you can use 'str' as the destination buffer
 * with the current implementation. always return the number of utf8 bytes corresponding to the original
 * message string, even if utf8 is NULL and utf8len is 0
 */
extern int  sms_utf8_from_message_str( const char*  str, int  strlen, unsigned char*  utf8, int  utf8len );

/* the equivalent in the opposite direction
 */
extern int  sms_utf8_to_message_str( const unsigned char*  utf8, int  utf8len, char*  str, int  strlen );

/** TIMESTAMPS
 **/

/* An SMS timestamp structure */
typedef struct {
    unsigned char  data[7];
} SmsTimeStampRec, *SmsTimeStamp;

extern void  sms_timestamp_now( SmsTimeStamp  stamp );
extern int   sms_timestamp_to_tm( SmsTimeStamp  stamp, struct tm*  tm );

/** SMS ADDRESSES
 **/

#define  SMS_ADDRESS_MAX_SIZE  16

typedef struct {
    unsigned char  len;
    unsigned char  toa;
    unsigned char  data[ SMS_ADDRESS_MAX_SIZE ];
} SmsAddressRec, *SmsAddress;

extern int  sms_address_from_str( SmsAddress  address, const char*  src, int  srclen );
extern int  sms_address_to_str( SmsAddress  address, char*  src, int  srclen );

extern int  sms_address_from_bytes( SmsAddress  address, const unsigned char*  buf, int  buflen );
extern int  sms_address_to_bytes  ( SmsAddress  address, unsigned char*  buf, int  bufsize );
extern int  sms_address_from_hex  ( SmsAddress  address, const char*  hex, int  hexlen );
extern int  sms_address_to_hex    ( SmsAddress  address, char*   hex, int  hexsize );

/** SMS PROTOCOL DATA UNITS
 **/

typedef struct SmsPDURec*   SmsPDU;

extern SmsPDU*  smspdu_create_deliver_utf8( const unsigned char*   utf8,
                                            int                    utf8len,
                                            const SmsAddressRec*   sender_address,
                                            const SmsTimeStampRec* timestamp );

extern void     smspdu_free_list( SmsPDU*  pdus );

extern SmsPDU   smspdu_create_from_hex( const char*  hex, int  hexlen );

extern int      smspdu_to_hex( SmsPDU  pdu, char*  hex, int  hexsize );

/* free a given SMS PDU */
extern void     smspdu_free( SmsPDU  pdu );

typedef enum {
    SMS_PDU_INVALID = 0,
    SMS_PDU_DELIVER,
    SMS_PDU_SUBMIT,
    SMS_PDU_STATUS_REPORT
} SmsPduType;

extern SmsPduType    smspdu_get_type( SmsPDU  pdu );

/* retrieve the sender address of a SMS-DELIVER pdu, returns -1 otherwise */
extern int  smspdu_get_sender_address( SmsPDU  pdu, SmsAddress  address );

/* retrieve the service center timestamp of a SMS-DELIVER pdu, return -1 otherwise */
extern int  smspdu_get_sc_timestamp( SmsPDU  pdu, SmsTimeStamp  timestamp );

/* retrieve the receiver address of a SMS-SUBMIT pdu, return -1 otherwise */
extern int  smspdu_get_receiver_address( SmsPDU  pdu, SmsAddress  address );

extern int  smspdu_get_ref      ( SmsPDU  pdu );
extern int  smspdu_get_max_index( SmsPDU  pdu );
extern int  smspdu_get_cur_index( SmsPDU  pdu );

/* get the message embedded in a SMS PDU as a utf8 byte array, returns the length of the message in bytes */
/* or -1 in case of error */
extern int  smspdu_get_text_message( SmsPDU  pdu, unsigned char*  utf8, int  utf8len );

/** SMS SUBMIT RECEIVER
 ** collects one or more SMS-SUBMIT PDUs to generate a single message to deliver
 **/

typedef struct SmsReceiverRec  *SmsReceiver;

extern SmsReceiver   sms_receiver_create( void );
extern void          sms_receiver_destroy( SmsReceiver  rec );

extern int           sms_receiver_add_submit_pdu( SmsReceiver  rec, SmsPDU       submit_pdu );
extern int           sms_receiver_get_text_message( SmsReceiver  rec, int  index, unsigned char*  utf8, int  utf8len );
extern SmsPDU*       sms_receiver_create_deliver( SmsReceiver  rec, int  index, const SmsAddressRec*  from );

#endif /* _android_sms_h */
