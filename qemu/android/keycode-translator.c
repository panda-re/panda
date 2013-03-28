
/*
struct TargetKeycode {
    unsigned int target_keycode;
    bool is_keydown; // vs. keyup
};

typedef struct TargetKeycode TargetKeycode_t;
*/

#include <stdbool.h>
#include "ui/keymaps.h"


#include "android/keycode-translator.h"
#include "android/keycode.h"
// Adapted from android/skin/keyboard.c ------------------------------------------
#include <SDL/SDL_keysym.h>
#if(0)
static AndroidKeyCode
skin_keyboard_key_to_code( 
                           unsigned       sym,
)
{
    AndroidKeyCode  code   = 0;
    
    switch (sym) {
        case SDLK_LEFT:       code = kKeyCodeDpadLeft; break;
        case SDLK_RIGHT:      code = kKeyCodeDpadRight; break;
        case SDLK_UP:         code = kKeyCodeDpadUp; break;
        case SDLK_DOWN:       code = kKeyCodeDpadDown; break;
        default: ;
    }
    
    if (code != 0) {
        D("handling arrow (sym=%d mod=%d)", sym, mod);
        if (!keyboard->raw_keys) {
            int  doCapL, doCapR, doAltL, doAltR;
            
            if (!down) {
                LastKey*  k = skin_keyboard_find_last(keyboard, sym);
                if (k != NULL) {
                    mod = k->mod;
                    skin_keyboard_remove_last( keyboard, sym );
                }
            } else {
                skin_keyboard_add_last( keyboard, sym, mod, 0);
            }
            
            doCapL = (mod & 0x7ff) & KMOD_LSHIFT;
            doCapR = (mod & 0x7ff) & KMOD_RSHIFT;
            doAltL = (mod & 0x7ff) & KMOD_LALT;
            doAltR = (mod & 0x7ff) & KMOD_RALT;
            
            if (down) {
                if (doAltL) skin_keyboard_add_key_event( keyboard, kKeyCodeAltLeft, 1 );
                if (doAltR) skin_keyboard_add_key_event( keyboard, kKeyCodeAltRight, 1 );
                if (doCapL) skin_keyboard_add_key_event( keyboard, kKeyCodeCapLeft, 1 );
                if (doCapR) skin_keyboard_add_key_event( keyboard, kKeyCodeCapRight, 1 );
            }
            skin_keyboard_add_key_event(keyboard, code, down);
            
            if (!down) {
                if (doCapR) skin_keyboard_add_key_event( keyboard, kKeyCodeCapRight, 0 );
                if (doCapL) skin_keyboard_add_key_event( keyboard, kKeyCodeCapLeft, 0 );
                if (doAltR) skin_keyboard_add_key_event( keyboard, kKeyCodeAltRight, 0 );
                if (doAltL) skin_keyboard_add_key_event( keyboard, kKeyCodeAltLeft, 0 );
            }
            code = 0;
        }
        return code;
    }
    
    /* special case for keypad keys, ignore them here if numlock is on */
    if ((mod0 & KMOD_NUM) != 0) {
        switch (sym) {
            case SDLK_KP0:
            case SDLK_KP1:
            case SDLK_KP2:
            case SDLK_KP3:
            case SDLK_KP4:
            case SDLK_KP5:
            case SDLK_KP6:
            case SDLK_KP7:
            case SDLK_KP8:
            case SDLK_KP9:
            case SDLK_KP_PLUS:
            case SDLK_KP_MINUS:
            case SDLK_KP_MULTIPLY:
            case SDLK_KP_DIVIDE:
            case SDLK_KP_EQUALS:
            case SDLK_KP_PERIOD:
            case SDLK_KP_ENTER:
                return 0;
        }
    }
    
    /* now try all keyset combos */
    command = skin_keyset_get_command( keyboard->kset, sym, mod );
    if (command != SKIN_KEY_COMMAND_NONE) {
        D("handling command %s from (sym=%d, mod=%d, str=%s)",
        skin_key_command_to_str(command), sym, mod, skin_key_symmod_to_str(sym,mod));
        skin_keyboard_cmd( keyboard, command, down );
        return 0;
    }
    D("could not handle (sym=%d, mod=%d, str=%s)", sym, mod,
    skin_key_symmod_to_str(sym,mod));
    return -1;
}
#endif
// END copied+modified code ------------------------------------------------------

// console.h says keycode is an int
//C++ would make this more pleasant
int translateToAndroid(AndroidKeycodeState_t* state, int keycode){
    //First first, if state.hasBit7 is clear, and keycode == 0x80, set it and bail
    if((false == state->hasBit7) && (SCANCODE_EMUL0 == keycode)){
        state->hasBit7 = true;
        //printf("Setting escape bit\n");
        return -1;
    }
    
    //First, check bit 7. If set, this is keyup)
    bool isdown = true;
    int result = 0;
    if (keycode & 0x80){
        isdown = false;
        keycode = keycode &~0x80;
    }
    if(state->hasBit7){
        //keycode = keycode | 0x80;
        state->hasBit7 = false;
    }
    
    
    // Now turn the PC keycode into an Android keycode.
    if (keycode < 97)
        result = keycode;
    else
        result = keycode;
    
    if (!isdown)
        return result;
    //printf("This is a keydown\n");
    return result | 0x200;
}
