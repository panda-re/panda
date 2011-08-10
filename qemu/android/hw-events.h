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
#ifndef _ANDROID_HW_EVENTS_H
#define _ANDROID_HW_EVENTS_H

#include "android/utils/system.h"

/* from the Linux kernel */

#define  EVENT_TYPE_LIST  \
  EV_TYPE(SYN,0x00)   \
  EV_TYPE(KEY,0x01)   \
  EV_TYPE(REL,0x02)   \
  EV_TYPE(ABS,0x03)   \
  EV_TYPE(MSC,0x04)   \
  EV_TYPE(SW, 0x05)   \
  EV_TYPE(LED,0x11)   \
  EV_TYPE(SND,0x12)   \
  EV_TYPE(REP,0x14)   \
  EV_TYPE(FF, 0x15)   \
  EV_TYPE(PWR,0x16)   \
  EV_TYPE(FF_STATUS,0x17)  \
  EV_TYPE(MAX,0x1f)

#undef  EV_TYPE
#define EV_TYPE(n,v)    GLUE(EV_,n) = v,
typedef enum {
    EVENT_TYPE_LIST
} EventType;
#undef  EV_TYPE

/* BEWARE: The following codes are defined by the Linux kernel headers.
 *         The Android "Menu" key is KEY_SOFT1, *not* KEY_MENU
 */
#define  EVENT_KEY_LIST \
   KEY_CODE(ESC         ,1)     \
   KEY_CODE(1           ,2)     \
   KEY_CODE(2           ,3)     \
   KEY_CODE(3           ,4)     \
   KEY_CODE(4           ,5)     \
   KEY_CODE(5           ,6)     \
   KEY_CODE(6           ,7)     \
   KEY_CODE(7           ,8)     \
   KEY_CODE(8           ,9)     \
   KEY_CODE(9           ,10)    \
   KEY_CODE(0           ,11)    \
   KEY_CODE(MINUS       ,12)    \
   KEY_CODE(EQUAL       ,13)    \
   KEY_CODE(BACKSPACE   ,14)    \
   KEY_CODE(TAB         ,15)    \
   KEY_CODE(Q           ,16)    \
   KEY_CODE(W           ,17)    \
   KEY_CODE(E           ,18)    \
   KEY_CODE(R           ,19)    \
   KEY_CODE(T           ,20)    \
   KEY_CODE(Y           ,21)    \
   KEY_CODE(U           ,22)    \
   KEY_CODE(I           ,23)    \
   KEY_CODE(O           ,24)    \
   KEY_CODE(P           ,25)    \
   KEY_CODE(LEFTBRACE   ,26)    \
   KEY_CODE(RIGHTBRACE  ,27)    \
   KEY_CODE(ENTER       ,28)    \
   KEY_CODE(LEFTCTRL    ,29)    \
   KEY_CODE(A           ,30)    \
   KEY_CODE(S           ,31)    \
   KEY_CODE(D           ,32)    \
   KEY_CODE(F           ,33)    \
   KEY_CODE(G           ,34)    \
   KEY_CODE(H           ,35)    \
   KEY_CODE(J           ,36)    \
   KEY_CODE(K           ,37)    \
   KEY_CODE(L           ,38)    \
   KEY_CODE(SEMICOLON   ,39)    \
   KEY_CODE(APOSTROPHE  ,40)    \
   KEY_CODE(GRAVE       ,41)    \
   KEY_CODE(LEFTSHIFT   ,42)    \
   KEY_CODE(BACKSLASH   ,43)    \
   KEY_CODE(Z           ,44)    \
   KEY_CODE(X           ,45)    \
   KEY_CODE(C           ,46)    \
   KEY_CODE(V           ,47)    \
   KEY_CODE(B           ,48)    \
   KEY_CODE(N           ,49)    \
   KEY_CODE(M           ,50)    \
   KEY_CODE(COMMA       ,51)    \
   KEY_CODE(DOT         ,52)    \
   KEY_CODE(SLASH       ,53)    \
   KEY_CODE(RIGHTSHIFT  ,54)    \
   KEY_CODE(KPASTERISK  ,55)    \
   KEY_CODE(LEFTALT     ,56)    \
   KEY_CODE(SPACE       ,57)    \
   KEY_CODE(CAPSLOCK    ,58)    \
   KEY_CODE(F1          ,59)    \
   KEY_CODE(F2          ,60)    \
   KEY_CODE(F3          ,61)    \
   KEY_CODE(F4          ,62)    \
   KEY_CODE(F5          ,63)    \
   KEY_CODE(F6          ,64)    \
   KEY_CODE(F7          ,65)    \
   KEY_CODE(F8          ,66)    \
   KEY_CODE(F9          ,67)    \
   KEY_CODE(F10         ,68)    \
   KEY_CODE(NUMLOCK     ,69)    \
   KEY_CODE(SCROLLLOCK  ,70)    \
   KEY_CODE(KP7         ,71)    \
   KEY_CODE(KP8         ,72)    \
   KEY_CODE(KP9         ,73)    \
   KEY_CODE(KPMINUS     ,74)    \
   KEY_CODE(KP4         ,75)    \
   KEY_CODE(KP5         ,76)    \
   KEY_CODE(KP6         ,77)    \
   KEY_CODE(KPPLUS      ,78)    \
   KEY_CODE(KP1         ,79)    \
   KEY_CODE(KP2         ,80)    \
   KEY_CODE(KP3         ,81)    \
   KEY_CODE(KP0         ,82)    \
   KEY_CODE(KPDOT       ,83)    \
   KEY_CODE(ZENKAKUHANKAKU,85)    \
   KEY_CODE(102ND       ,86)    \
   KEY_CODE(F11         ,87)    \
   KEY_CODE(F12         ,88)    \
   KEY_CODE(RO          ,89)    \
   KEY_CODE(KATAKANA    ,90)    \
   KEY_CODE(HIRAGANA    ,91)    \
   KEY_CODE(HENKAN      ,92)    \
   KEY_CODE(KATAKANAHIRAGANA,93)    \
   KEY_CODE(MUHENKAN    ,94)    \
   KEY_CODE(KPJPCOMMA   ,95)    \
   KEY_CODE(KPENTER     ,96)    \
   KEY_CODE(RIGHTCTRL   ,97)    \
   KEY_CODE(KPSLASH     ,98)    \
   KEY_CODE(SYSRQ       ,99)    \
   KEY_CODE(RIGHTALT    ,100)   \
   KEY_CODE(LINEFEED    ,101)   \
   KEY_CODE(HOME        ,102)   \
   KEY_CODE(UP          ,103)   \
   KEY_CODE(PAGEUP      ,104)   \
   KEY_CODE(LEFT        ,105)   \
   KEY_CODE(RIGHT       ,106)   \
   KEY_CODE(END         ,107)   \
   KEY_CODE(DOWN        ,108)   \
   KEY_CODE(PAGEDOWN    ,109)   \
   KEY_CODE(INSERT      ,110)   \
   KEY_CODE(DELETE      ,111)   \
   KEY_CODE(MACRO       ,112)   \
   KEY_CODE(MUTE        ,113)   \
   KEY_CODE(VOLUMEDOWN  ,114)   \
   KEY_CODE(VOLUMEUP    ,115)   \
   KEY_CODE(POWER       ,116)   \
   KEY_CODE(KPEQUAL     ,117)   \
   KEY_CODE(KPPLUSMINUS ,118)   \
   KEY_CODE(PAUSE       ,119)   \
   KEY_CODE(KPCOMMA     ,121)   \
   KEY_CODE(HANGEUL     ,122)   \
   KEY_CODE(HANJA       ,123)   \
   KEY_CODE(YEN         ,124)   \
   KEY_CODE(LEFTMETA    ,125)   \
   KEY_CODE(RIGHTMETA   ,126)   \
   KEY_CODE(COMPOSE     ,127)   \
   KEY_CODE(STOP        ,128)   \
   KEY_CODE(AGAIN       ,129)   \
   KEY_CODE(PROPS       ,130)   \
   KEY_CODE(UNDO        ,131)   \
   KEY_CODE(FRONT       ,132)   \
   KEY_CODE(COPY        ,133)   \
   KEY_CODE(OPEN        ,134)   \
   KEY_CODE(PASTE       ,135)   \
   KEY_CODE(FIND        ,136)   \
   KEY_CODE(CUT         ,137)   \
   KEY_CODE(HELP        ,138)   \
   KEY_CODE(MENU        ,139)   \
   KEY_CODE(CALC        ,140)   \
   KEY_CODE(SETUP       ,141)   \
   KEY_CODE(SLEEP       ,142)   \
   KEY_CODE(WAKEUP      ,143)   \
   KEY_CODE(FILE        ,144)   \
   KEY_CODE(SENDFILE    ,145)   \
   KEY_CODE(DELETEFILE  ,146)   \
   KEY_CODE(XFER        ,147)   \
   KEY_CODE(PROG1       ,148)   \
   KEY_CODE(PROG2       ,149)   \
   KEY_CODE(WWW         ,150)   \
   KEY_CODE(MSDOS       ,151)   \
   KEY_CODE(COFFEE      ,152)   \
   KEY_CODE(DIRECTION   ,153)   \
   KEY_CODE(CYCLEWINDOWS,154)   \
   KEY_CODE(MAIL        ,155)   \
   KEY_CODE(BOOKMARKS   ,156)   \
   KEY_CODE(COMPUTER    ,157)   \
   KEY_CODE(BACK        ,158)   \
   KEY_CODE(FORWARD     ,159)   \
   KEY_CODE(CLOSECD     ,160)   \
   KEY_CODE(EJECTCD     ,161)   \
   KEY_CODE(EJECTCLOSECD,162)   \
   KEY_CODE(NEXTSONG    ,163)   \
   KEY_CODE(PLAYPAUSE   ,164)   \
   KEY_CODE(PREVIOUSSONG,165)   \
   KEY_CODE(STOPCD      ,166)   \
   KEY_CODE(RECORD      ,167)   \
   KEY_CODE(REWIND      ,168)   \
   KEY_CODE(PHONE       ,169)   \
   KEY_CODE(ISO         ,170)   \
   KEY_CODE(CONFIG      ,171)   \
   KEY_CODE(HOMEPAGE    ,172)   \
   KEY_CODE(REFRESH     ,173)   \
   KEY_CODE(EXIT        ,174)   \
   KEY_CODE(MOVE        ,175)   \
   KEY_CODE(EDIT        ,176)   \
   KEY_CODE(SCROLLUP    ,177)   \
   KEY_CODE(SCROLLDOWN  ,178)   \
   KEY_CODE(KPLEFTPAREN ,179)   \
   KEY_CODE(KPRIGHTPAREN,180)   \
   KEY_CODE(NEW         ,181)   \
   KEY_CODE(REDO        ,182)   \
   KEY_CODE(F13         ,183)   \
   KEY_CODE(F14         ,184)   \
   KEY_CODE(F15         ,185)   \
   KEY_CODE(F16         ,186)   \
   KEY_CODE(F17         ,187)   \
   KEY_CODE(F18         ,188)   \
   KEY_CODE(F19         ,189)   \
   KEY_CODE(F20         ,190)   \
   KEY_CODE(F21         ,191)   \
   KEY_CODE(F22         ,192)   \
   KEY_CODE(F23         ,193)   \
   KEY_CODE(F24         ,194)   \
   KEY_CODE(PLAYCD      ,200)   \
   KEY_CODE(PAUSECD     ,201)   \
   KEY_CODE(PROG3       ,202)   \
   KEY_CODE(PROG4       ,203)   \
   KEY_CODE(SUSPEND     ,205)   \
   KEY_CODE(CLOSE       ,206)   \
   KEY_CODE(PLAY        ,207)   \
   KEY_CODE(FASTFORWARD ,208)   \
   KEY_CODE(BASSBOOST   ,209)   \
   KEY_CODE(PRINT       ,210)   \
   KEY_CODE(HP          ,211)   \
   KEY_CODE(CAMERA      ,212)   \
   KEY_CODE(SOUND       ,213)   \
   KEY_CODE(QUESTION    ,214)   \
   KEY_CODE(EMAIL       ,215)   \
   KEY_CODE(CHAT        ,216)   \
   KEY_CODE(SEARCH      ,217)   \
   KEY_CODE(CONNECT     ,218)   \
   KEY_CODE(FINANCE     ,219)   \
   KEY_CODE(SPORT       ,220)   \
   KEY_CODE(SHOP        ,221)   \
   KEY_CODE(ALTERASE    ,222)   \
   KEY_CODE(CANCEL      ,223)   \
   KEY_CODE(BRIGHTNESSDOWN,224)   \
   KEY_CODE(BRIGHTNESSUP,225)   \
   KEY_CODE(MEDIA       ,226)   \
   KEY_CODE(STAR        ,227)   \
   KEY_CODE(SHARP       ,228)   \
   KEY_CODE(SOFT1       ,229)   \
   KEY_CODE(SOFT2       ,230)   \
   KEY_CODE(SEND        ,231)   \
   KEY_CODE(CENTER      ,232)   \
   KEY_CODE(HEADSETHOOK ,233)   \
   KEY_CODE(0_5         ,234)   \
   KEY_CODE(2_5         ,235)   \
   KEY_CODE(SWITCHVIDEOMODE,236)   \
   KEY_CODE(KBDILLUMTOGGLE,237)   \
   KEY_CODE(KBDILLUMDOWN,238)   \
   KEY_CODE(KBDILLUMUP  ,239)   \
   KEY_CODE(REPLY       ,232)   \
   KEY_CODE(FORWARDMAIL ,233)   \
   KEY_CODE(SAVE        ,234)   \
   KEY_CODE(DOCUMENTS   ,235)   \
   KEY_CODE(BATTERY     ,236)   \
   KEY_CODE(UNKNOWN     ,240)   \
   KEY_CODE(NUM         ,241)   \
   KEY_CODE(FOCUS       ,242)   \
   KEY_CODE(PLUS        ,243)   \
   KEY_CODE(NOTIFICATION,244)   \
   KEY_CODE(OK          ,0x160)  \
   KEY_CODE(SELECT      ,0x161)  \
   KEY_CODE(GOTO        ,0x162)  \
   KEY_CODE(CLEAR       ,0x163)  \
   KEY_CODE(POWER2      ,0x164)  \
   KEY_CODE(OPTION      ,0x165)  \
   KEY_CODE(INFO        ,0x166)  \
   KEY_CODE(TIME        ,0x167)  \
   KEY_CODE(VENDOR      ,0x168)  \
   KEY_CODE(ARCHIVE     ,0x169)  \
   KEY_CODE(PROGRAM     ,0x16a)  \
   KEY_CODE(CHANNEL     ,0x16b)  \
   KEY_CODE(FAVORITES   ,0x16c)  \
   KEY_CODE(EPG         ,0x16d)  \
   KEY_CODE(PVR         ,0x16e)  \
   KEY_CODE(MHP         ,0x16f)  \
   KEY_CODE(LANGUAGE    ,0x170)  \
   KEY_CODE(TITLE       ,0x171)  \
   KEY_CODE(SUBTITLE    ,0x172)  \
   KEY_CODE(ANGLE       ,0x173)  \
   KEY_CODE(ZOOM        ,0x174)  \
   KEY_CODE(MODE        ,0x175)  \
   KEY_CODE(KEYBOARD    ,0x176)  \
   KEY_CODE(SCREEN      ,0x177)  \
   KEY_CODE(PC          ,0x178)  \
   KEY_CODE(TV          ,0x179)  \
   KEY_CODE(TV2         ,0x17a)  \
   KEY_CODE(VCR         ,0x17b)  \
   KEY_CODE(VCR2        ,0x17c)  \
   KEY_CODE(SAT         ,0x17d)  \
   KEY_CODE(SAT2        ,0x17e)  \
   KEY_CODE(CD          ,0x17f)  \
   KEY_CODE(TAPE        ,0x180)  \
   KEY_CODE(RADIO       ,0x181)  \
   KEY_CODE(TUNER       ,0x182)  \
   KEY_CODE(PLAYER      ,0x183)  \
   KEY_CODE(TEXT        ,0x184)  \
   KEY_CODE(DVD         ,0x185)  \
   KEY_CODE(AUX         ,0x186)  \
   KEY_CODE(MP3         ,0x187)  \
   KEY_CODE(AUDIO       ,0x188)  \
   KEY_CODE(VIDEO       ,0x189)  \
   KEY_CODE(DIRECTORY   ,0x18a)  \
   KEY_CODE(LIST        ,0x18b)  \
   KEY_CODE(MEMO        ,0x18c)  \
   KEY_CODE(CALENDAR    ,0x18d)  \
   KEY_CODE(RED         ,0x18e)  \
   KEY_CODE(GREEN       ,0x18f)  \
   KEY_CODE(YELLOW      ,0x190)  \
   KEY_CODE(BLUE        ,0x191)  \
   KEY_CODE(CHANNELUP   ,0x192)  \
   KEY_CODE(CHANNELDOWN ,0x193)  \
   KEY_CODE(FIRST       ,0x194)  \
   KEY_CODE(LAST        ,0x195)  \
   KEY_CODE(AB          ,0x196)  \
   KEY_CODE(NEXT        ,0x197)  \
   KEY_CODE(RESTART     ,0x198)  \
   KEY_CODE(SLOW        ,0x199)  \
   KEY_CODE(SHUFFLE     ,0x19a)  \
   KEY_CODE(BREAK       ,0x19b)  \
   KEY_CODE(PREVIOUS    ,0x19c)  \
   KEY_CODE(DIGITS      ,0x19d)  \
   KEY_CODE(TEEN        ,0x19e)  \
   KEY_CODE(TWEN        ,0x19f)  \
   KEY_CODE(DEL_EOL     ,0x1c0)  \
   KEY_CODE(DEL_EOS     ,0x1c1)  \
   KEY_CODE(INS_LINE    ,0x1c2)  \
   KEY_CODE(DEL_LINE    ,0x1c3)  \
   KEY_CODE(FN          ,0x1d0)  \
   KEY_CODE(FN_ESC      ,0x1d1)  \
   KEY_CODE(FN_F1       ,0x1d2)  \
   KEY_CODE(FN_F2       ,0x1d3)  \
   KEY_CODE(FN_F3       ,0x1d4)  \
   KEY_CODE(FN_F4       ,0x1d5)  \
   KEY_CODE(FN_F5       ,0x1d6)  \
   KEY_CODE(FN_F6       ,0x1d7)  \
   KEY_CODE(FN_F7       ,0x1d8)  \
   KEY_CODE(FN_F8       ,0x1d9)  \
   KEY_CODE(FN_F9       ,0x1da)  \
   KEY_CODE(FN_F10      ,0x1db)  \
   KEY_CODE(FN_F11      ,0x1dc)  \
   KEY_CODE(FN_F12      ,0x1dd)  \
   KEY_CODE(FN_1        ,0x1de)  \
   KEY_CODE(FN_2        ,0x1df)  \
   KEY_CODE(FN_D        ,0x1e0)  \
   KEY_CODE(FN_E        ,0x1e1)  \
   KEY_CODE(FN_F        ,0x1e2)  \
   KEY_CODE(FN_S        ,0x1e3)  \
   KEY_CODE(FN_B        ,0x1e4)  \
   KEY_CODE(BRL_DOT1    ,0x1f1)  \
   KEY_CODE(BRL_DOT2    ,0x1f2)  \
   KEY_CODE(BRL_DOT3    ,0x1f3)  \
   KEY_CODE(BRL_DOT4    ,0x1f4)  \
   KEY_CODE(BRL_DOT5    ,0x1f5)  \
   KEY_CODE(BRL_DOT6    ,0x1f6)  \
   KEY_CODE(BRL_DOT7    ,0x1f7)  \
   KEY_CODE(BRL_DOT8    ,0x1f8)  \

#undef  KEY_CODE
#define KEY_CODE(n,v)   GLUE(KEY_,n) = v,
typedef enum {
    EVENT_KEY_LIST
} EventKeyCode;
#undef  KEY_CODE


#define  EVENT_BTN_LIST  \
    BTN_CODE(MISC,0x100)  \
    BTN_CODE(0,0x100)     \
    BTN_CODE(1,0x101)     \
    BTN_CODE(2,0x102)     \
    BTN_CODE(3,0x103)     \
    BTN_CODE(4,0x104)     \
    BTN_CODE(5,0x105)     \
    BTN_CODE(6,0x106)     \
    BTN_CODE(7,0x107)     \
    BTN_CODE(8,0x108)     \
    BTN_CODE(9,0x109)     \
    \
    BTN_CODE(MOUSE,  0x110)  \
    BTN_CODE(LEFT,   0x110)  \
    BTN_CODE(RIGHT,  0x111)  \
    BTN_CODE(MIDDLE, 0x112)  \
    BTN_CODE(SIDE,   0x113)  \
    BTN_CODE(EXTRA,  0x114)  \
    BTN_CODE(FORWARD,0x115)  \
    BTN_CODE(BACK,   0x116)  \
    BTN_CODE(TASK,   0x117)  \
    \
    BTN_CODE(JOYSTICK,0x120)  \
    BTN_CODE(TRIGGER, 0x120)  \
    BTN_CODE(THUMB,   0x121)  \
    BTN_CODE(THUMB2,  0x122)  \
    BTN_CODE(TOP,     0x123)  \
    BTN_CODE(TOP2,    0x124)  \
    BTN_CODE(PINKIE,  0x125)  \
    BTN_CODE(BASE,    0x126)  \
    BTN_CODE(BASE2,   0x127)  \
    BTN_CODE(BASE3,   0x128)  \
    BTN_CODE(BASE4,   0x129)  \
    BTN_CODE(BASE5,   0x12a)  \
    BTN_CODE(BASE6,   0x12b)  \
    BTN_CODE(DEAD,    0x12f)  \
    \
    BTN_CODE(GAMEPAD,  0x130)  \
    BTN_CODE(A,        0x130)  \
    BTN_CODE(B,        0x131)  \
    BTN_CODE(C,        0x132)  \
    BTN_CODE(X,        0x133)  \
    BTN_CODE(Y,        0x134)  \
    BTN_CODE(Z,        0x135)  \
    BTN_CODE(TL,       0x136)  \
    BTN_CODE(TR,       0x137)  \
    BTN_CODE(TL2,      0x138)  \
    BTN_CODE(TR2,      0x139)  \
    BTN_CODE(SELECT,   0x13a)  \
    BTN_CODE(START,    0x13b)  \
    BTN_CODE(MODE,     0x13c)  \
    BTN_CODE(THUMBL,   0x13d)  \
    BTN_CODE(THUMBR,   0x13e)  \
    \
    BTN_CODE(DIGI,            0x140)  \
    BTN_CODE(TOOL_PEN,        0x140)  \
    BTN_CODE(TOOL_RUBBER,     0x141)  \
    BTN_CODE(TOOL_BRUSH,      0x142)  \
    BTN_CODE(TOOL_PENCIL,     0x143)  \
    BTN_CODE(TOOL_AIRBRUSH,   0x144)  \
    BTN_CODE(TOOL_FINGER,     0x145)  \
    BTN_CODE(TOOL_MOUSE,      0x146)  \
    BTN_CODE(TOOL_LENS,       0x147)  \
    BTN_CODE(TOUCH,           0x14a)  \
    BTN_CODE(STYLUS,          0x14b)  \
    BTN_CODE(STYLUS2,         0x14c)  \
    BTN_CODE(TOOL_DOUBLETAP,  0x14d)  \
    BTN_CODE(TOOL_TRIPLETAP,  0x14e)  \
    \
    BTN_CODE(WHEEL,  0x150)      \
    BTN_CODE(GEAR_DOWN,  0x150)  \
    BTN_CODE(GEAR_UP,    0x150)

#undef  BTN_CODE
#define BTN_CODE(n,v)   GLUE(BTN_,n) = v,
typedef enum {
    EVENT_BTN_LIST
} EventBtnCode;
#undef  BTN_CODE

#define  EVENT_REL_LIST \
    REL_CODE(X,  0x00)  \
    REL_CODE(Y,  0x01)

#define  REL_CODE(n,v)  GLUE(REL_,n) = v,
typedef enum {
    EVENT_REL_LIST
} EventRelCode;
#undef  REL_CODE

#define  EVENT_ABS_LIST  \
    ABS_CODE(X,        0x00)  \
    ABS_CODE(Y,        0x01)  \
    ABS_CODE(Z,        0x02)  \
    ABS_CODE(RX,       0x03)  \
    ABS_CODE(RY,       0x04)  \
    ABS_CODE(RZ,       0x05)  \
    ABS_CODE(THROTTLE, 0x06)  \
    ABS_CODE(RUDDER,   0x07)  \
    ABS_CODE(WHEEL,    0x08)  \
    ABS_CODE(GAS,      0x09)  \
    ABS_CODE(BRAKE,    0x0a)  \
    ABS_CODE(HAT0X,    0x10)  \
    ABS_CODE(HAT0Y,    0x11)  \
    ABS_CODE(HAT1X,    0x12)  \
    ABS_CODE(HAT1Y,    0x13)  \
    ABS_CODE(HAT2X,    0x14)  \
    ABS_CODE(HAT2Y,    0x15)  \
    ABS_CODE(HAT3X,    0x16)  \
    ABS_CODE(HAT3Y,    0x17)  \
    ABS_CODE(PRESSURE, 0x18)  \
    ABS_CODE(DISTANCE, 0x19)  \
    ABS_CODE(TILT_X,   0x1a)  \
    ABS_CODE(TILT_Y,   0x1b)  \
    ABS_CODE(TOOL_WIDTH, 0x1c)  \
    ABS_CODE(VOLUME,     0x20)  \
    ABS_CODE(MISC,       0x28)  \
    ABS_CODE(MAX,        0x3f)

#define  ABS_CODE(n,v)  GLUE(ABS_,n) = v,

typedef enum {
    EVENT_ABS_LIST
} EventAbsCode;
#undef  ABS_CODE

/* convert an event string specification like <type>:<code>:<value>
 * into three integers. returns 0 on success, or -1 in case of error
 */
extern int   android_event_from_str( const char*  name,
                                     int         *ptype,
                                     int         *pcode,
                                     int         *pvalue );

/* returns the list of valid event type string aliases */
extern int    android_event_get_type_count( void );
extern char*  android_event_bufprint_type_str( char*  buff, char*  end, int  type_index );

/* returns the list of valid event code string aliases for a given event type */
extern int    android_event_get_code_count( int  type );
extern char*  android_event_bufprint_code_str( char*  buff, char*  end, int  type, int  code_index );

#endif /* _ANDROID_HW_EVENTS_H */
