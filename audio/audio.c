/*
 * QEMU Audio subsystem
 *
 * Copyright (c) 2003-2005 Vassili Karpov (malc)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "hw/hw.h"
#include "audio.h"
#include "monitor/monitor.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "qemu/cutils.h"
#include "sysemu/replay.h"

#define AUDIO_CAP "audio"
#include "audio_int.h"

/* #define DEBUG_LIVE */
/* #define DEBUG_OUT */
/* #define DEBUG_CAPTURE */
/* #define DEBUG_POLL */

#define SW_NAME(sw) (sw)->name ? (sw)->name : "unknown"


/* Order of CONFIG_AUDIO_DRIVERS is import.
   The 1st one is the one used by default, that is the reason
    that we generate the list.
*/
static struct audio_driver *drvtab[] = {
#ifdef CONFIG_SPICE
    &spice_audio_driver,
#endif
    CONFIG_AUDIO_DRIVERS
    &no_audio_driver,
    &wav_audio_driver
};

struct fixed_settings {
    int enabled;
    int nb_voices;
    int greedy;
    struct audsettings settings;
};

static struct {
    struct fixed_settings fixed_out;
    struct fixed_settings fixed_in;
    union {
        int hertz;
        int64_t ticks;
    } period;
    int try_poll_in;
    int try_poll_out;
} conf = {
    .fixed_out = { /* DAC fixed settings */
        .enabled = 1,
        .nb_voices = 1,
        .greedy = 1,
        .settings = {
            .freq = 44100,
            .nchannels = 2,
            .fmt = AUD_FMT_S16,
            .endianness =  AUDIO_HOST_ENDIANNESS,
        }
    },

    .fixed_in = { /* ADC fixed settings */
        .enabled = 1,
        .nb_voices = 1,
        .greedy = 1,
        .settings = {
            .freq = 44100,
            .nchannels = 2,
            .fmt = AUD_FMT_S16,
            .endianness = AUDIO_HOST_ENDIANNESS,
        }
    },

    .period = { .hertz = 100 },
    .try_poll_in = 1,
    .try_poll_out = 1,
};

static AudioState glob_audio_state;

const struct mixeng_volume nominal_volume = {
    .mute = 0,
#ifdef FLOAT_MIXENG
    .r = 1.0,
    .l = 1.0,
#else
    .r = 1ULL << 32,
    .l = 1ULL << 32,
#endif
};

#ifdef AUDIO_IS_FLAWLESS_AND_NO_CHECKS_ARE_REQURIED
#error No its not
#else
static void audio_print_options (const char *prefix,
                                 struct audio_option *opt);

int audio_bug (const char *funcname, int cond)
{
    if (cond) {
        static int shown;

        AUD_log (NULL, "A bug was just triggered in %s\n", funcname);
        if (!shown) {
            struct audio_driver *d;

            shown = 1;
            AUD_log (NULL, "Save all your work and restart without audio\n");
            AUD_log (NULL, "Please send bug report to av1474@comtv.ru\n");
            AUD_log (NULL, "I am sorry\n");
            d = glob_audio_state.drv;
            if (d) {
                audio_print_options (d->name, d->options);
            }
        }
        AUD_log (NULL, "Context:\n");

#if defined AUDIO_BREAKPOINT_ON_BUG
#  if defined HOST_I386
#    if defined __GNUC__
        __asm__ ("int3");
#    elif defined _MSC_VER
        _asm _emit 0xcc;
#    else
        abort ();
#    endif
#  else
        abort ();
#  endif
#endif
    }

    return cond;
}
#endif

static inline int audio_bits_to_index (int bits)
{
    switch (bits) {
    case 8:
        return 0;

    case 16:
        return 1;

    case 32:
        return 2;

    default:
        audio_bug ("bits_to_index", 1);
        AUD_log (NULL, "invalid bits %d\n", bits);
        return 0;
    }
}

void *audio_calloc (const char *funcname, int nmemb, size_t size)
{
    int cond;
    size_t len;

    len = nmemb * size;
    cond = !nmemb || !size;
    cond |= nmemb < 0;
    cond |= len < size;

    if (audio_bug ("audio_calloc", cond)) {
        AUD_log (NULL, "%s passed invalid arguments to audio_calloc\n",
                 funcname);
        AUD_log (NULL, "nmemb=%d size=%zu (len=%zu)\n", nmemb, size, len);
        return NULL;
    }

    return g_malloc0 (len);
}

static char *audio_alloc_prefix (const char *s)
{
    const char qemu_prefix[] = "QEMU_";
    size_t len, i;
    char *r, *u;

    if (!s) {
        return NULL;
    }

    len = strlen (s);
    r = g_malloc (len + sizeof (qemu_prefix));

    u = r + sizeof (qemu_prefix) - 1;

    pstrcpy (r, len + sizeof (qemu_prefix), qemu_prefix);
    pstrcat (r, len + sizeof (qemu_prefix), s);

    for (i = 0; i < len; ++i) {
        u[i] = qemu_toupper(u[i]);
    }

    return r;
}

static const char *audio_audfmt_to_string (audfmt_e fmt)
{
    switch (fmt) {
    case AUD_FMT_U8:
        return "U8";

    case AUD_FMT_U16:
        return "U16";

    case AUD_FMT_S8:
        return "S8";

    case AUD_FMT_S16:
        return "S16";

    case AUD_FMT_U32:
        return "U32";

    case AUD_FMT_S32:
        return "S32";
    }

    dolog ("Bogus audfmt %d returning S16\n", fmt);
    return "S16";
}

static audfmt_e audio_string_to_audfmt (const char *s, audfmt_e defval,
                                        int *defaultp)
{
    if (!strcasecmp (s, "u8")) {
        *defaultp = 0;
        return AUD_FMT_U8;
    }
    else if (!strcasecmp (s, "u16")) {
        *defaultp = 0;
        return AUD_FMT_U16;
    }
    else if (!strcasecmp (s, "u32")) {
        *defaultp = 0;
        return AUD_FMT_U32;
    }
    else if (!strcasecmp (s, "s8")) {
        *defaultp = 0;
        return AUD_FMT_S8;
    }
    else if (!strcasecmp (s, "s16")) {
        *defaultp = 0;
        return AUD_FMT_S16;
    }
    else if (!strcasecmp (s, "s32")) {
        *defaultp = 0;
        return AUD_FMT_S32;
    }
    else {
        dolog ("Bogus audio format `%s' using %s\n",
               s, audio_audfmt_to_string (defval));
        *defaultp = 1;
        return defval;
    }
}

static audfmt_e audio_get_conf_fmt (const char *envname,
                                    audfmt_e defval,
                                    int *defaultp)
{
    const char *var = getenv (envname);
    if (!var) {
        *defaultp = 1;
        return defval;
    }
    return audio_string_to_audfmt (var, defval, defaultp);
}

static int audio_get_conf_int (const char *key, int defval, int *defaultp)
{
    int val;
    char *strval;

    strval = getenv (key);
    if (strval) {
        *defaultp = 0;
        val = atoi (strval);
        return val;
    }
    else {
        *defaultp = 1;
        return defval;
    }
}

static const char *audio_get_conf_str (const char *key,
                                       const char *defval,
                                       int *defaultp)
{
    const char *val = getenv (key);
    if (!val) {
        *defaultp = 1;
        return defval;
    }
    else {
        *defaultp = 0;
        return val;
    }
}

void AUD_vlog (const char *cap, const char *fmt, va_list ap)
{
    if (cap) {
        fprintf(stderr, "%s: ", cap);
    }

    vfprintf(stderr, fmt, ap);
}

void AUD_log (const char *cap, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    AUD_vlog (cap, fmt, ap);
    va_end (ap);
}

static void audio_print_options (const char *prefix,
                                 struct audio_option *opt)
{
    char *uprefix;

    if (!prefix) {
        dolog ("No prefix specified\n");
        return;
    }

    if (!opt) {
        dolog ("No options\n");
        return;
    }

    uprefix = audio_alloc_prefix (prefix);

    for (; opt->name; opt++) {
        const char *state = "default";
        printf ("  %s_%s: ", uprefix, opt->name);

        if (opt->overriddenp && *opt->overriddenp) {
            state = "current";
        }

        switch (opt->tag) {
        case AUD_OPT_BOOL:
            {
                int *intp = opt->valp;
                printf ("boolean, %s = %d\n", state, *intp ? 1 : 0);
            }
            break;

        case AUD_OPT_INT:
            {
                int *intp = opt->valp;
                printf ("integer, %s = %d\n", state, *intp);
            }
            break;

        case AUD_OPT_FMT:
            {
                audfmt_e *fmtp = opt->valp;
                printf (
                    "format, %s = %s, (one of: U8 S8 U16 S16 U32 S32)\n",
                    state,
                    audio_audfmt_to_string (*fmtp)
                    );
            }
            break;

        case AUD_OPT_STR:
            {
                const char **strp = opt->valp;
                printf ("string, %s = %s\n",
                        state,
                        *strp ? *strp : "(not set)");
            }
            break;

        default:
            printf ("???\n");
            dolog ("Bad value tag for option %s_%s %d\n",
                   uprefix, opt->name, opt->tag);
            break;
        }
        printf ("    %s\n", opt->descr);
    }

    g_free (uprefix);
}

static void audio_process_options (const char *prefix,
                                   struct audio_option *opt)
{
    char *optname;
    const char qemu_prefix[] = "QEMU_";
    size_t preflen, optlen;

    if (audio_bug (AUDIO_FUNC, !prefix)) {
        dolog ("prefix = NULL\n");
        return;
    }

    if (audio_bug (AUDIO_FUNC, !opt)) {
        dolog ("opt = NULL\n");
        return;
    }

    preflen = strlen (prefix);

    for (; opt->name; opt++) {
        size_t len, i;
        int def;

        if (!opt->valp) {
            dolog ("Option value pointer for `%s' is not set\n",
                   opt->name);
            continue;
        }

        len = strlen (opt->name);
        /* len of opt->name + len of prefix + size of qemu_prefix
         * (includes trailing zero) + zero + underscore (on behalf of
         * sizeof) */
        optlen = len + preflen + sizeof (qemu_prefix) + 1;
        optname = g_malloc (optlen);

        pstrcpy (optname, optlen, qemu_prefix);

        /* copy while upper-casing, including trailing zero */
        for (i = 0; i <= preflen; ++i) {
            optname[i + sizeof (qemu_prefix) - 1] = qemu_toupper(prefix[i]);
        }
        pstrcat (optname, optlen, "_");
        pstrcat (optname, optlen, opt->name);

        def = 1;
        switch (opt->tag) {
        case AUD_OPT_BOOL:
        case AUD_OPT_INT:
            {
                int *intp = opt->valp;
                *intp = audio_get_conf_int (optname, *intp, &def);
            }
            break;

        case AUD_OPT_FMT:
            {
                audfmt_e *fmtp = opt->valp;
                *fmtp = audio_get_conf_fmt (optname, *fmtp, &def);
            }
            break;

        case AUD_OPT_STR:
            {
                const char **strp = opt->valp;
                *strp = audio_get_conf_str (optname, *strp, &def);
            }
            break;

        default:
            dolog ("Bad value tag for option `%s' - %d\n",
                   optname, opt->tag);
            break;
        }

        if (!opt->overriddenp) {
            opt->overriddenp = &opt->overridden;
        }
        *opt->overriddenp = !def;
        g_free (optname);
    }
}

static void audio_print_settings (struct audsettings *as)
{
    dolog ("frequency=%d nchannels=%d fmt=", as->freq, as->nchannels);

    switch (as->fmt) {
    case AUD_FMT_S8:
        AUD_log (NULL, "S8");
        break;
    case AUD_FMT_U8:
        AUD_log (NULL, "U8");
        break;
    case AUD_FMT_S16:
        AUD_log (NULL, "S16");
        break;
    case AUD_FMT_U16:
        AUD_log (NULL, "U16");
        break;
    case AUD_FMT_S32:
        AUD_log (NULL, "S32");
        break;
    case AUD_FMT_U32:
        AUD_log (NULL, "U32");
        break;
    default:
        AUD_log (NULL, "invalid(%d)", as->fmt);
        break;
    }

    AUD_log (NULL, " endianness=");
    switch (as->endianness) {
    case 0:
        AUD_log (NULL, "little");
        break;
    case 1:
        AUD_log (NULL, "big");
        break;
    default:
        AUD_log (NULL, "invalid");
        break;
    }
    AUD_log (NULL, "\n");
}

static int audio_validate_settings (struct audsettings *as)
{
    int invalid;

    invalid = as->nchannels != 1 && as->nchannels != 2;
    invalid |= as->endianness != 0 && as->endianness != 1;

    switch (as->fmt) {
    case AUD_FMT_S8:
    case AUD_FMT_U8:
    case AUD_FMT_S16:
    case AUD_FMT_U16:
    case AUD_FMT_S32:
    case AUD_FMT_U32:
        break;
    default:
        invalid = 1;
        break;
    }

    invalid |= as->freq <= 0;
    return invalid ? -1 : 0;
}

static int audio_pcm_info_eq (struct audio_pcm_info *info, struct audsettings *as)
{
    int bits = 8, sign = 0;

    switch (as->fmt) {
    case AUD_FMT_S8:
        sign = 1;
        /* fall through */
    case AUD_FMT_U8:
        break;

    case AUD_FMT_S16:
        sign = 1;
        /* fall through */
    case AUD_FMT_U16:
        bits = 16;
        break;

    case AUD_FMT_S32:
        sign = 1;
        /* fall through */
    case AUD_FMT_U32:
        bits = 32;
        break;
    }
    return info->freq == as->freq
        && info->nchannels == as->nchannels
        && info->sign == sign
        && info->bits == bits
        && info->swap_endianness == (as->endianness != AUDIO_HOST_ENDIANNESS);
}

void audio_pcm_init_info (struct audio_pcm_info *info, struct audsettings *as)
{
    int bits = 8, sign = 0, shift = 0;

    switch (as->fmt) {
    case AUD_FMT_S8:
        sign = 1;
    case AUD_FMT_U8:
        break;

    case AUD_FMT_S16:
        sign = 1;
    case AUD_FMT_U16:
        bits = 16;
        shift = 1;
        break;

    case AUD_FMT_S32:
        sign = 1;
    case AUD_FMT_U32:
        bits = 32;
        shift = 2;
        break;
    }

    info->freq = as->freq;
    info->bits = bits;
    info->sign = sign;
    info->nchannels = as->nchannels;
    info->shift = (as->nchannels == 2) + shift;
    info->align = (1 << info->shift) - 1;
    info->bytes_per_second = info->freq << info->shift;
    info->swap_endianness = (as->endianness != AUDIO_HOST_ENDIANNESS);
}

void audio_pcm_info_clear_buf (struct audio_pcm_info *info, void *buf, int len)
{
    if (!len) {
        return;
    }

    if (info->sign) {
        memset (buf, 0x00, len << info->shift);
    }
    else {
        switch (info->bits) {
        case 8:
            memset (buf, 0x80, len << info->shift);
            break;

        case 16:
            {
                int i;
                uint16_t *p = buf;
                int shift = info->nchannels - 1;
                short s = INT16_MAX;

                if (info->swap_endianness) {
                    s = bswap16 (s);
                }

                for (i = 0; i < len << shift; i++) {
                    p[i] = s;
                }
            }
            break;

        case 32:
            {
                int i;
                uint32_t *p = buf;
                int shift = info->nchannels - 1;
                int32_t s = INT32_MAX;

                if (info->swap_endianness) {
                    s = bswap32 (s);
                }

                for (i = 0; i < len << shift; i++) {
                    p[i] = s;
                }
            }
            break;

        default:
            AUD_log (NULL, "audio_pcm_info_clear_buf: invalid bits %d\n",
                     info->bits);
            break;
        }
    }
}

/*
 * Capture
 */
static void noop_conv (struct st_sample *dst, const void *src, int samples)
{
    (void) src;
    (void) dst;
    (void) samples;
}

static CaptureVoiceOut *audio_pcm_capture_find_specific (
    struct audsettings *as
    )
{
    CaptureVoiceOut *cap;
    AudioState *s = &glob_audio_state;

    for (cap = s->cap_head.lh_first; cap; cap = cap->entries.le_next) {
        if (audio_pcm_info_eq (&cap->hw.info, as)) {
            return cap;
        }
    }
    return NULL;
}

static void audio_notify_capture (CaptureVoiceOut *cap, audcnotification_e cmd)
{
    struct capture_callback *cb;

#ifdef DEBUG_CAPTURE
    dolog ("notification %d sent\n", cmd);
#endif
    for (cb = cap->cb_head.lh_first; cb; cb = cb->entries.le_next) {
        cb->ops.notify (cb->opaque, cmd);
    }
}

static void audio_capture_maybe_changed (CaptureVoiceOut *cap, int enabled)
{
    if (cap->hw.enabled != enabled) {
        audcnotification_e cmd;
        cap->hw.enabled = enabled;
        cmd = enabled ? AUD_CNOTIFY_ENABLE : AUD_CNOTIFY_DISABLE;
        audio_notify_capture (cap, cmd);
    }
}

static void audio_recalc_and_notify_capture (CaptureVoiceOut *cap)
{
    HWVoiceOut *hw = &cap->hw;
    SWVoiceOut *sw;
    int enabled = 0;

    for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
        if (sw->active) {
            enabled = 1;
            break;
        }
    }
    audio_capture_maybe_changed (cap, enabled);
}

static void audio_detach_capture (HWVoiceOut *hw)
{
    SWVoiceCap *sc = hw->cap_head.lh_first;

    while (sc) {
        SWVoiceCap *sc1 = sc->entries.le_next;
        SWVoiceOut *sw = &sc->sw;
        CaptureVoiceOut *cap = sc->cap;
        int was_active = sw->active;

        if (sw->rate) {
            st_rate_stop (sw->rate);
            sw->rate = NULL;
        }

        QLIST_REMOVE (sw, entries);
        QLIST_REMOVE (sc, entries);
        g_free (sc);
        if (was_active) {
            /* We have removed soft voice from the capture:
               this might have changed the overall status of the capture
               since this might have been the only active voice */
            audio_recalc_and_notify_capture (cap);
        }
        sc = sc1;
    }
}

static int audio_attach_capture (HWVoiceOut *hw)
{
    AudioState *s = &glob_audio_state;
    CaptureVoiceOut *cap;

    audio_detach_capture (hw);
    for (cap = s->cap_head.lh_first; cap; cap = cap->entries.le_next) {
        SWVoiceCap *sc;
        SWVoiceOut *sw;
        HWVoiceOut *hw_cap = &cap->hw;

        sc = audio_calloc (AUDIO_FUNC, 1, sizeof (*sc));
        if (!sc) {
            dolog ("Could not allocate soft capture voice (%zu bytes)\n",
                   sizeof (*sc));
            return -1;
        }

        sc->cap = cap;
        sw = &sc->sw;
        sw->hw = hw_cap;
        sw->info = hw->info;
        sw->empty = 1;
        sw->active = hw->enabled;
        sw->conv = noop_conv;
        sw->ratio = ((int64_t) hw_cap->info.freq << 32) / sw->info.freq;
        sw->vol = nominal_volume;
        sw->rate = st_rate_start (sw->info.freq, hw_cap->info.freq);
        if (!sw->rate) {
            dolog ("Could not start rate conversion for `%s'\n", SW_NAME (sw));
            g_free (sw);
            return -1;
        }
        QLIST_INSERT_HEAD (&hw_cap->sw_head, sw, entries);
        QLIST_INSERT_HEAD (&hw->cap_head, sc, entries);
#ifdef DEBUG_CAPTURE
        sw->name = g_strdup_printf ("for %p %d,%d,%d",
                                    hw, sw->info.freq, sw->info.bits,
                                    sw->info.nchannels);
        dolog ("Added %s active = %d\n", sw->name, sw->active);
#endif
        if (sw->active) {
            audio_capture_maybe_changed (cap, 1);
        }
    }
    return 0;
}

/*
 * Hard voice (capture)
 */
static int audio_pcm_hw_find_min_in (HWVoiceIn *hw)
{
    SWVoiceIn *sw;
    int m = hw->total_samples_captured;

    for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
        if (sw->active) {
            m = audio_MIN (m, sw->total_hw_samples_acquired);
        }
    }
    return m;
}

int audio_pcm_hw_get_live_in (HWVoiceIn *hw)
{
    int live = hw->total_samples_captured - audio_pcm_hw_find_min_in (hw);
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }
    return live;
}

int audio_pcm_hw_clip_out (HWVoiceOut *hw, void *pcm_buf,
                           int live, int pending)
{
    int left = hw->samples - pending;
    int len = audio_MIN (left, live);
    int clipped = 0;

    while (len) {
        struct st_sample *src = hw->mix_buf + hw->rpos;
        uint8_t *dst = advance (pcm_buf, hw->rpos << hw->info.shift);
        int samples_till_end_of_buf = hw->samples - hw->rpos;
        int samples_to_clip = audio_MIN (len, samples_till_end_of_buf);

        hw->clip (dst, src, samples_to_clip);

        hw->rpos = (hw->rpos + samples_to_clip) % hw->samples;
        len -= samples_to_clip;
        clipped += samples_to_clip;
    }
    return clipped;
}

/*
 * Soft voice (capture)
 */
static int audio_pcm_sw_get_rpos_in (SWVoiceIn *sw)
{
    HWVoiceIn *hw = sw->hw;
    int live = hw->total_samples_captured - sw->total_hw_samples_acquired;
    int rpos;

    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }

    rpos = hw->wpos - live;
    if (rpos >= 0) {
        return rpos;
    }
    else {
        return hw->samples + rpos;
    }
}

int audio_pcm_sw_read (SWVoiceIn *sw, void *buf, int size)
{
    HWVoiceIn *hw = sw->hw;
    int samples, live, ret = 0, swlim, isamp, osamp, rpos, total = 0;
    struct st_sample *src, *dst = sw->buf;

    rpos = audio_pcm_sw_get_rpos_in (sw) % hw->samples;

    live = hw->total_samples_captured - sw->total_hw_samples_acquired;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live_in=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }

    samples = size >> sw->info.shift;
    if (!live) {
        return 0;
    }

    swlim = (live * sw->ratio) >> 32;
    swlim = audio_MIN (swlim, samples);

    while (swlim) {
        src = hw->conv_buf + rpos;
        isamp = hw->wpos - rpos;
        /* XXX: <= ? */
        if (isamp <= 0) {
            isamp = hw->samples - rpos;
        }

        if (!isamp) {
            break;
        }
        osamp = swlim;

        if (audio_bug (AUDIO_FUNC, osamp < 0)) {
            dolog ("osamp=%d\n", osamp);
            return 0;
        }

        st_rate_flow (sw->rate, src, dst, &isamp, &osamp);
        swlim -= osamp;
        rpos = (rpos + isamp) % hw->samples;
        dst += osamp;
        ret += osamp;
        total += isamp;
    }

    if (!(hw->ctl_caps & VOICE_VOLUME_CAP)) {
        mixeng_volume (sw->buf, ret, &sw->vol);
    }

    sw->clip (buf, sw->buf, ret);
    sw->total_hw_samples_acquired += total;
    return ret << sw->info.shift;
}

/*
 * Hard voice (playback)
 */
static int audio_pcm_hw_find_min_out (HWVoiceOut *hw, int *nb_livep)
{
    SWVoiceOut *sw;
    int m = INT_MAX;
    int nb_live = 0;

    for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
        if (sw->active || !sw->empty) {
            m = audio_MIN (m, sw->total_hw_samples_mixed);
            nb_live += 1;
        }
    }

    *nb_livep = nb_live;
    return m;
}

static int audio_pcm_hw_get_live_out (HWVoiceOut *hw, int *nb_live)
{
    int smin;
    int nb_live1;

    smin = audio_pcm_hw_find_min_out (hw, &nb_live1);
    if (nb_live) {
        *nb_live = nb_live1;
    }

    if (nb_live1) {
        int live = smin;

        if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
            dolog ("live=%d hw->samples=%d\n", live, hw->samples);
            return 0;
        }
        return live;
    }
    return 0;
}

/*
 * Soft voice (playback)
 */
int audio_pcm_sw_write (SWVoiceOut *sw, void *buf, int size)
{
    int hwsamples, samples, isamp, osamp, wpos, live, dead, left, swlim, blck;
    int ret = 0, pos = 0, total = 0;

    if (!sw) {
        return size;
    }

    hwsamples = sw->hw->samples;

    live = sw->total_hw_samples_mixed;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hwsamples)){
        dolog ("live=%d hw->samples=%d\n", live, hwsamples);
        return 0;
    }

    if (live == hwsamples) {
#ifdef DEBUG_OUT
        dolog ("%s is full %d\n", sw->name, live);
#endif
        return 0;
    }

    wpos = (sw->hw->rpos + live) % hwsamples;
    samples = size >> sw->info.shift;

    dead = hwsamples - live;
    swlim = ((int64_t) dead << 32) / sw->ratio;
    swlim = audio_MIN (swlim, samples);
    if (swlim) {
        sw->conv (sw->buf, buf, swlim);

        if (!(sw->hw->ctl_caps & VOICE_VOLUME_CAP)) {
            mixeng_volume (sw->buf, swlim, &sw->vol);
        }
    }

    while (swlim) {
        dead = hwsamples - live;
        left = hwsamples - wpos;
        blck = audio_MIN (dead, left);
        if (!blck) {
            break;
        }
        isamp = swlim;
        osamp = blck;
        st_rate_flow_mix (
            sw->rate,
            sw->buf + pos,
            sw->hw->mix_buf + wpos,
            &isamp,
            &osamp
            );
        ret += isamp;
        swlim -= isamp;
        pos += isamp;
        live += osamp;
        wpos = (wpos + osamp) % hwsamples;
        total += osamp;
    }

    sw->total_hw_samples_mixed += total;
    sw->empty = sw->total_hw_samples_mixed == 0;

#ifdef DEBUG_OUT
    dolog (
        "%s: write size %d ret %d total sw %d\n",
        SW_NAME (sw),
        size >> sw->info.shift,
        ret,
        sw->total_hw_samples_mixed
        );
#endif

    return ret << sw->info.shift;
}

#ifdef DEBUG_AUDIO
static void audio_pcm_print_info (const char *cap, struct audio_pcm_info *info)
{
    dolog ("%s: bits %d, sign %d, freq %d, nchan %d\n",
           cap, info->bits, info->sign, info->freq, info->nchannels);
}
#endif

#define DAC
#include "audio_template.h"
#undef DAC
#include "audio_template.h"

/*
 * Timer
 */
static int audio_is_timer_needed (void)
{
    HWVoiceIn *hwi = NULL;
    HWVoiceOut *hwo = NULL;

    while ((hwo = audio_pcm_hw_find_any_enabled_out (hwo))) {
        if (!hwo->poll_mode) return 1;
    }
    while ((hwi = audio_pcm_hw_find_any_enabled_in (hwi))) {
        if (!hwi->poll_mode) return 1;
    }
    return 0;
}

static void audio_reset_timer (AudioState *s)
{
    if (audio_is_timer_needed ()) {
        timer_mod_anticipate_ns(s->ts,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + conf.period.ticks);
    }
    else {
        timer_del (s->ts);
    }
}

static void audio_timer (void *opaque)
{
    audio_run ("timer");
    audio_reset_timer (opaque);
}

/*
 * Public API
 */
int AUD_write (SWVoiceOut *sw, void *buf, int size)
{
    if (!sw) {
        /* XXX: Consider options */
        return size;
    }

    if (!sw->hw->enabled) {
        dolog ("Writing to disabled voice %s\n", SW_NAME (sw));
        return 0;
    }

    return sw->hw->pcm_ops->write(sw, buf, size);
}

int AUD_read (SWVoiceIn *sw, void *buf, int size)
{
    if (!sw) {
        /* XXX: Consider options */
        return size;
    }

    if (!sw->hw->enabled) {
        dolog ("Reading from disabled voice %s\n", SW_NAME (sw));
        return 0;
    }

    return sw->hw->pcm_ops->read(sw, buf, size);
}

int AUD_get_buffer_size_out (SWVoiceOut *sw)
{
    return sw->hw->samples << sw->hw->info.shift;
}

void AUD_set_active_out (SWVoiceOut *sw, int on)
{
    HWVoiceOut *hw;

    if (!sw) {
        return;
    }

    hw = sw->hw;
    if (sw->active != on) {
        AudioState *s = &glob_audio_state;
        SWVoiceOut *temp_sw;
        SWVoiceCap *sc;

        if (on) {
            hw->pending_disable = 0;
            if (!hw->enabled) {
                hw->enabled = 1;
                if (s->vm_running) {
                    hw->pcm_ops->ctl_out (hw, VOICE_ENABLE, conf.try_poll_out);
                    audio_reset_timer (s);
                }
            }
        }
        else {
            if (hw->enabled) {
                int nb_active = 0;

                for (temp_sw = hw->sw_head.lh_first; temp_sw;
                     temp_sw = temp_sw->entries.le_next) {
                    nb_active += temp_sw->active != 0;
                }

                hw->pending_disable = nb_active == 1;
            }
        }

        for (sc = hw->cap_head.lh_first; sc; sc = sc->entries.le_next) {
            sc->sw.active = hw->enabled;
            if (hw->enabled) {
                audio_capture_maybe_changed (sc->cap, 1);
            }
        }
        sw->active = on;
    }
}

void AUD_set_active_in (SWVoiceIn *sw, int on)
{
    HWVoiceIn *hw;

    if (!sw) {
        return;
    }

    hw = sw->hw;
    if (sw->active != on) {
        AudioState *s = &glob_audio_state;
        SWVoiceIn *temp_sw;

        if (on) {
            if (!hw->enabled) {
                hw->enabled = 1;
                if (s->vm_running) {
                    hw->pcm_ops->ctl_in (hw, VOICE_ENABLE, conf.try_poll_in);
                    audio_reset_timer (s);
                }
            }
            sw->total_hw_samples_acquired = hw->total_samples_captured;
        }
        else {
            if (hw->enabled) {
                int nb_active = 0;

                for (temp_sw = hw->sw_head.lh_first; temp_sw;
                     temp_sw = temp_sw->entries.le_next) {
                    nb_active += temp_sw->active != 0;
                }

                if (nb_active == 1) {
                    hw->enabled = 0;
                    hw->pcm_ops->ctl_in (hw, VOICE_DISABLE);
                }
            }
        }
        sw->active = on;
    }
}

static int audio_get_avail (SWVoiceIn *sw)
{
    int live;

    if (!sw) {
        return 0;
    }

    live = sw->hw->total_samples_captured - sw->total_hw_samples_acquired;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > sw->hw->samples)) {
        dolog ("live=%d sw->hw->samples=%d\n", live, sw->hw->samples);
        return 0;
    }

    ldebug (
        "%s: get_avail live %d ret %" PRId64 "\n",
        SW_NAME (sw),
        live, (((int64_t) live << 32) / sw->ratio) << sw->info.shift
        );

    return (((int64_t) live << 32) / sw->ratio) << sw->info.shift;
}

static int audio_get_free (SWVoiceOut *sw)
{
    int live, dead;

    if (!sw) {
        return 0;
    }

    live = sw->total_hw_samples_mixed;

    if (audio_bug (AUDIO_FUNC, live < 0 || live > sw->hw->samples)) {
        dolog ("live=%d sw->hw->samples=%d\n", live, sw->hw->samples);
        return 0;
    }

    dead = sw->hw->samples - live;

#ifdef DEBUG_OUT
    dolog ("%s: get_free live %d dead %d ret %" PRId64 "\n",
           SW_NAME (sw),
           live, dead, (((int64_t) dead << 32) / sw->ratio) << sw->info.shift);
#endif

    return (((int64_t) dead << 32) / sw->ratio) << sw->info.shift;
}

static void audio_capture_mix_and_clear (HWVoiceOut *hw, int rpos, int samples)
{
    int n;

    if (hw->enabled) {
        SWVoiceCap *sc;

        for (sc = hw->cap_head.lh_first; sc; sc = sc->entries.le_next) {
            SWVoiceOut *sw = &sc->sw;
            int rpos2 = rpos;

            n = samples;
            while (n) {
                int till_end_of_hw = hw->samples - rpos2;
                int to_write = audio_MIN (till_end_of_hw, n);
                int bytes = to_write << hw->info.shift;
                int written;

                sw->buf = hw->mix_buf + rpos2;
                written = audio_pcm_sw_write (sw, NULL, bytes);
                if (written - bytes) {
                    dolog ("Could not mix %d bytes into a capture "
                           "buffer, mixed %d\n",
                           bytes, written);
                    break;
                }
                n -= to_write;
                rpos2 = (rpos2 + to_write) % hw->samples;
            }
        }
    }

    n = audio_MIN (samples, hw->samples - rpos);
    mixeng_clear (hw->mix_buf + rpos, n);
    mixeng_clear (hw->mix_buf, samples - n);
}

static void audio_run_out (AudioState *s)
{
    HWVoiceOut *hw = NULL;
    SWVoiceOut *sw;

    while ((hw = audio_pcm_hw_find_any_enabled_out (hw))) {
        int played;
        int live, free, nb_live, cleanup_required, prev_rpos;

        live = audio_pcm_hw_get_live_out (hw, &nb_live);
        if (!nb_live) {
            live = 0;
        }

        if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
            dolog ("live=%d hw->samples=%d\n", live, hw->samples);
            continue;
        }

        if (hw->pending_disable && !nb_live) {
            SWVoiceCap *sc;
#ifdef DEBUG_OUT
            dolog ("Disabling voice\n");
#endif
            hw->enabled = 0;
            hw->pending_disable = 0;
            hw->pcm_ops->ctl_out (hw, VOICE_DISABLE);
            for (sc = hw->cap_head.lh_first; sc; sc = sc->entries.le_next) {
                sc->sw.active = 0;
                audio_recalc_and_notify_capture (sc->cap);
            }
            continue;
        }

        if (!live) {
            for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
                if (sw->active) {
                    free = audio_get_free (sw);
                    if (free > 0) {
                        sw->callback.fn (sw->callback.opaque, free);
                    }
                }
            }
            continue;
        }

        prev_rpos = hw->rpos;
        played = hw->pcm_ops->run_out (hw, live);
        replay_audio_out(&played);
        if (audio_bug (AUDIO_FUNC, hw->rpos >= hw->samples)) {
            dolog ("hw->rpos=%d hw->samples=%d played=%d\n",
                   hw->rpos, hw->samples, played);
            hw->rpos = 0;
        }

#ifdef DEBUG_OUT
        dolog ("played=%d\n", played);
#endif

        if (played) {
            hw->ts_helper += played;
            audio_capture_mix_and_clear (hw, prev_rpos, played);
        }

        cleanup_required = 0;
        for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
            if (!sw->active && sw->empty) {
                continue;
            }

            if (audio_bug (AUDIO_FUNC, played > sw->total_hw_samples_mixed)) {
                dolog ("played=%d sw->total_hw_samples_mixed=%d\n",
                       played, sw->total_hw_samples_mixed);
                played = sw->total_hw_samples_mixed;
            }

            sw->total_hw_samples_mixed -= played;

            if (!sw->total_hw_samples_mixed) {
                sw->empty = 1;
                cleanup_required |= !sw->active && !sw->callback.fn;
            }

            if (sw->active) {
                free = audio_get_free (sw);
                if (free > 0) {
                    sw->callback.fn (sw->callback.opaque, free);
                }
            }
        }

        if (cleanup_required) {
            SWVoiceOut *sw1;

            sw = hw->sw_head.lh_first;
            while (sw) {
                sw1 = sw->entries.le_next;
                if (!sw->active && !sw->callback.fn) {
                    audio_close_out (sw);
                }
                sw = sw1;
            }
        }
    }
}

static void audio_run_in (AudioState *s)
{
    HWVoiceIn *hw = NULL;

    while ((hw = audio_pcm_hw_find_any_enabled_in (hw))) {
        SWVoiceIn *sw;
        int captured = 0, min;

        if (replay_mode != REPLAY_MODE_PLAY) {
            captured = hw->pcm_ops->run_in(hw);
        }
        replay_audio_in(&captured, hw->conv_buf, &hw->wpos, hw->samples);

        min = audio_pcm_hw_find_min_in (hw);
        hw->total_samples_captured += captured - min;
        hw->ts_helper += captured;

        for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
            sw->total_hw_samples_acquired -= min;

            if (sw->active) {
                int avail;

                avail = audio_get_avail (sw);
                if (avail > 0) {
                    sw->callback.fn (sw->callback.opaque, avail);
                }
            }
        }
    }
}

static void audio_run_capture (AudioState *s)
{
    CaptureVoiceOut *cap;

    for (cap = s->cap_head.lh_first; cap; cap = cap->entries.le_next) {
        int live, rpos, captured;
        HWVoiceOut *hw = &cap->hw;
        SWVoiceOut *sw;

        captured = live = audio_pcm_hw_get_live_out (hw, NULL);
        rpos = hw->rpos;
        while (live) {
            int left = hw->samples - rpos;
            int to_capture = audio_MIN (live, left);
            struct st_sample *src;
            struct capture_callback *cb;

            src = hw->mix_buf + rpos;
            hw->clip (cap->buf, src, to_capture);
            mixeng_clear (src, to_capture);

            for (cb = cap->cb_head.lh_first; cb; cb = cb->entries.le_next) {
                cb->ops.capture (cb->opaque, cap->buf,
                                 to_capture << hw->info.shift);
            }
            rpos = (rpos + to_capture) % hw->samples;
            live -= to_capture;
        }
        hw->rpos = rpos;

        for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
            if (!sw->active && sw->empty) {
                continue;
            }

            if (audio_bug (AUDIO_FUNC, captured > sw->total_hw_samples_mixed)) {
                dolog ("captured=%d sw->total_hw_samples_mixed=%d\n",
                       captured, sw->total_hw_samples_mixed);
                captured = sw->total_hw_samples_mixed;
            }

            sw->total_hw_samples_mixed -= captured;
            sw->empty = sw->total_hw_samples_mixed == 0;
        }
    }
}

void audio_run (const char *msg)
{
    AudioState *s = &glob_audio_state;

    audio_run_out (s);
    audio_run_in (s);
    audio_run_capture (s);
#ifdef DEBUG_POLL
    {
        static double prevtime;
        double currtime;
        struct timeval tv;

        if (gettimeofday (&tv, NULL)) {
            perror ("audio_run: gettimeofday");
            return;
        }

        currtime = tv.tv_sec + tv.tv_usec * 1e-6;
        dolog ("Elapsed since last %s: %f\n", msg, currtime - prevtime);
        prevtime = currtime;
    }
#endif
}

static struct audio_option audio_options[] = {
    /* DAC */
    {
        .name  = "DAC_FIXED_SETTINGS",
        .tag   = AUD_OPT_BOOL,
        .valp  = &conf.fixed_out.enabled,
        .descr = "Use fixed settings for host DAC"
    },
    {
        .name  = "DAC_FIXED_FREQ",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_out.settings.freq,
        .descr = "Frequency for fixed host DAC"
    },
    {
        .name  = "DAC_FIXED_FMT",
        .tag   = AUD_OPT_FMT,
        .valp  = &conf.fixed_out.settings.fmt,
        .descr = "Format for fixed host DAC"
    },
    {
        .name  = "DAC_FIXED_CHANNELS",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_out.settings.nchannels,
        .descr = "Number of channels for fixed DAC (1 - mono, 2 - stereo)"
    },
    {
        .name  = "DAC_VOICES",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_out.nb_voices,
        .descr = "Number of voices for DAC"
    },
    {
        .name  = "DAC_TRY_POLL",
        .tag   = AUD_OPT_BOOL,
        .valp  = &conf.try_poll_out,
        .descr = "Attempt using poll mode for DAC"
    },
    /* ADC */
    {
        .name  = "ADC_FIXED_SETTINGS",
        .tag   = AUD_OPT_BOOL,
        .valp  = &conf.fixed_in.enabled,
        .descr = "Use fixed settings for host ADC"
    },
    {
        .name  = "ADC_FIXED_FREQ",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_in.settings.freq,
        .descr = "Frequency for fixed host ADC"
    },
    {
        .name  = "ADC_FIXED_FMT",
        .tag   = AUD_OPT_FMT,
        .valp  = &conf.fixed_in.settings.fmt,
        .descr = "Format for fixed host ADC"
    },
    {
        .name  = "ADC_FIXED_CHANNELS",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_in.settings.nchannels,
        .descr = "Number of channels for fixed ADC (1 - mono, 2 - stereo)"
    },
    {
        .name  = "ADC_VOICES",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.fixed_in.nb_voices,
        .descr = "Number of voices for ADC"
    },
    {
        .name  = "ADC_TRY_POLL",
        .tag   = AUD_OPT_BOOL,
        .valp  = &conf.try_poll_in,
        .descr = "Attempt using poll mode for ADC"
    },
    /* Misc */
    {
        .name  = "TIMER_PERIOD",
        .tag   = AUD_OPT_INT,
        .valp  = &conf.period.hertz,
        .descr = "Timer period in HZ (0 - use lowest possible)"
    },
    { /* End of list */ }
};

static void audio_pp_nb_voices (const char *typ, int nb)
{
    switch (nb) {
    case 0:
        printf ("Does not support %s\n", typ);
        break;
    case 1:
        printf ("One %s voice\n", typ);
        break;
    case INT_MAX:
        printf ("Theoretically supports many %s voices\n", typ);
        break;
    default:
        printf ("Theoretically supports up to %d %s voices\n", nb, typ);
        break;
    }

}

void AUD_help (void)
{
    size_t i;

    audio_process_options ("AUDIO", audio_options);
    for (i = 0; i < ARRAY_SIZE (drvtab); i++) {
        struct audio_driver *d = drvtab[i];
        if (d->options) {
            audio_process_options (d->name, d->options);
        }
    }

    printf ("Audio options:\n");
    audio_print_options ("AUDIO", audio_options);
    printf ("\n");

    printf ("Available drivers:\n");

    for (i = 0; i < ARRAY_SIZE (drvtab); i++) {
        struct audio_driver *d = drvtab[i];

        printf ("Name: %s\n", d->name);
        printf ("Description: %s\n", d->descr);

        audio_pp_nb_voices ("playback", d->max_voices_out);
        audio_pp_nb_voices ("capture", d->max_voices_in);

        if (d->options) {
            printf ("Options:\n");
            audio_print_options (d->name, d->options);
        }
        else {
            printf ("No options\n");
        }
        printf ("\n");
    }

    printf (
        "Options are settable through environment variables.\n"
        "Example:\n"
#ifdef _WIN32
        "  set QEMU_AUDIO_DRV=wav\n"
        "  set QEMU_WAV_PATH=c:\\tune.wav\n"
#else
        "  export QEMU_AUDIO_DRV=wav\n"
        "  export QEMU_WAV_PATH=$HOME/tune.wav\n"
        "(for csh replace export with setenv in the above)\n"
#endif
        "  qemu ...\n\n"
        );
}

static int audio_driver_init (AudioState *s, struct audio_driver *drv)
{
    if (drv->options) {
        audio_process_options (drv->name, drv->options);
    }
    s->drv_opaque = drv->init ();

    if (s->drv_opaque) {
        audio_init_nb_voices_out (drv);
        audio_init_nb_voices_in (drv);
        s->drv = drv;
        return 0;
    }
    else {
        dolog ("Could not init `%s' audio driver\n", drv->name);
        return -1;
    }
}

static void audio_vm_change_state_handler (void *opaque, int running,
                                           RunState state)
{
    AudioState *s = opaque;
    HWVoiceOut *hwo = NULL;
    HWVoiceIn *hwi = NULL;
    int op = running ? VOICE_ENABLE : VOICE_DISABLE;

    s->vm_running = running;
    while ((hwo = audio_pcm_hw_find_any_enabled_out (hwo))) {
        hwo->pcm_ops->ctl_out (hwo, op, conf.try_poll_out);
    }

    while ((hwi = audio_pcm_hw_find_any_enabled_in (hwi))) {
        hwi->pcm_ops->ctl_in (hwi, op, conf.try_poll_in);
    }
    audio_reset_timer (s);
}

static bool is_cleaning_up;

bool audio_is_cleaning_up(void)
{
    return is_cleaning_up;
}

void audio_cleanup(void)
{
    AudioState *s = &glob_audio_state;
    HWVoiceOut *hwo, *hwon;
    HWVoiceIn *hwi, *hwin;

    is_cleaning_up = true;
    QLIST_FOREACH_SAFE(hwo, &glob_audio_state.hw_head_out, entries, hwon) {
        SWVoiceCap *sc;

        if (hwo->enabled) {
            hwo->pcm_ops->ctl_out (hwo, VOICE_DISABLE);
        }
        hwo->pcm_ops->fini_out (hwo);

        for (sc = hwo->cap_head.lh_first; sc; sc = sc->entries.le_next) {
            CaptureVoiceOut *cap = sc->cap;
            struct capture_callback *cb;

            for (cb = cap->cb_head.lh_first; cb; cb = cb->entries.le_next) {
                cb->ops.destroy (cb->opaque);
            }
        }
        QLIST_REMOVE(hwo, entries);
    }

    QLIST_FOREACH_SAFE(hwi, &glob_audio_state.hw_head_in, entries, hwin) {
        if (hwi->enabled) {
            hwi->pcm_ops->ctl_in (hwi, VOICE_DISABLE);
        }
        hwi->pcm_ops->fini_in (hwi);
        QLIST_REMOVE(hwi, entries);
    }

    if (s->drv) {
        s->drv->fini (s->drv_opaque);
        s->drv = NULL;
    }
}

static const VMStateDescription vmstate_audio = {
    .name = "audio",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST()
    }
};

static void audio_init (void)
{
    size_t i;
    int done = 0;
    const char *drvname;
    VMChangeStateEntry *e;
    AudioState *s = &glob_audio_state;

    if (s->drv) {
        return;
    }

    QLIST_INIT (&s->hw_head_out);
    QLIST_INIT (&s->hw_head_in);
    QLIST_INIT (&s->cap_head);
    atexit(audio_cleanup);

    s->ts = timer_new_ns(QEMU_CLOCK_VIRTUAL, audio_timer, s);

    audio_process_options ("AUDIO", audio_options);

    s->nb_hw_voices_out = conf.fixed_out.nb_voices;
    s->nb_hw_voices_in = conf.fixed_in.nb_voices;

    if (s->nb_hw_voices_out <= 0) {
        dolog ("Bogus number of playback voices %d, setting to 1\n",
               s->nb_hw_voices_out);
        s->nb_hw_voices_out = 1;
    }

    if (s->nb_hw_voices_in <= 0) {
        dolog ("Bogus number of capture voices %d, setting to 0\n",
               s->nb_hw_voices_in);
        s->nb_hw_voices_in = 0;
    }

    {
        int def;
        drvname = audio_get_conf_str ("QEMU_AUDIO_DRV", NULL, &def);
    }

    if (drvname) {
        int found = 0;

        for (i = 0; i < ARRAY_SIZE (drvtab); i++) {
            if (!strcmp (drvname, drvtab[i]->name)) {
                done = !audio_driver_init (s, drvtab[i]);
                found = 1;
                break;
            }
        }

        if (!found) {
            dolog ("Unknown audio driver `%s'\n", drvname);
            dolog ("Run with -audio-help to list available drivers\n");
        }
    }

    if (!done) {
        for (i = 0; !done && i < ARRAY_SIZE (drvtab); i++) {
            if (drvtab[i]->can_be_default) {
                done = !audio_driver_init (s, drvtab[i]);
            }
        }
    }

    if (!done) {
        done = !audio_driver_init (s, &no_audio_driver);
        assert(done);
        dolog("warning: Using timer based audio emulation\n");
    }

    if (conf.period.hertz <= 0) {
        if (conf.period.hertz < 0) {
            dolog ("warning: Timer period is negative - %d "
                   "treating as zero\n",
                   conf.period.hertz);
        }
        conf.period.ticks = 1;
    } else {
        conf.period.ticks = NANOSECONDS_PER_SECOND / conf.period.hertz;
    }

    e = qemu_add_vm_change_state_handler (audio_vm_change_state_handler, s);
    if (!e) {
        dolog ("warning: Could not register change state handler\n"
               "(Audio can continue looping even after stopping the VM)\n");
    }

    QLIST_INIT (&s->card_head);
    vmstate_register (NULL, 0, &vmstate_audio, s);
}

void AUD_register_card (const char *name, QEMUSoundCard *card)
{
    audio_init ();
    card->name = g_strdup (name);
    memset (&card->entries, 0, sizeof (card->entries));
    QLIST_INSERT_HEAD (&glob_audio_state.card_head, card, entries);
}

void AUD_remove_card (QEMUSoundCard *card)
{
    QLIST_REMOVE (card, entries);
    g_free (card->name);
}


CaptureVoiceOut *AUD_add_capture (
    struct audsettings *as,
    struct audio_capture_ops *ops,
    void *cb_opaque
    )
{
    AudioState *s = &glob_audio_state;
    CaptureVoiceOut *cap;
    struct capture_callback *cb;

    if (audio_validate_settings (as)) {
        dolog ("Invalid settings were passed when trying to add capture\n");
        audio_print_settings (as);
        goto err0;
    }

    cb = audio_calloc (AUDIO_FUNC, 1, sizeof (*cb));
    if (!cb) {
        dolog ("Could not allocate capture callback information, size %zu\n",
               sizeof (*cb));
        goto err0;
    }
    cb->ops = *ops;
    cb->opaque = cb_opaque;

    cap = audio_pcm_capture_find_specific (as);
    if (cap) {
        QLIST_INSERT_HEAD (&cap->cb_head, cb, entries);
        return cap;
    }
    else {
        HWVoiceOut *hw;
        CaptureVoiceOut *cap;

        cap = audio_calloc (AUDIO_FUNC, 1, sizeof (*cap));
        if (!cap) {
            dolog ("Could not allocate capture voice, size %zu\n",
                   sizeof (*cap));
            goto err1;
        }

        hw = &cap->hw;
        QLIST_INIT (&hw->sw_head);
        QLIST_INIT (&cap->cb_head);

        /* XXX find a more elegant way */
        hw->samples = 4096 * 4;
        hw->mix_buf = audio_calloc (AUDIO_FUNC, hw->samples,
                                    sizeof (struct st_sample));
        if (!hw->mix_buf) {
            dolog ("Could not allocate capture mix buffer (%d samples)\n",
                   hw->samples);
            goto err2;
        }

        audio_pcm_init_info (&hw->info, as);

        cap->buf = audio_calloc (AUDIO_FUNC, hw->samples, 1 << hw->info.shift);
        if (!cap->buf) {
            dolog ("Could not allocate capture buffer "
                   "(%d samples, each %d bytes)\n",
                   hw->samples, 1 << hw->info.shift);
            goto err3;
        }

        hw->clip = mixeng_clip
            [hw->info.nchannels == 2]
            [hw->info.sign]
            [hw->info.swap_endianness]
            [audio_bits_to_index (hw->info.bits)];

        QLIST_INSERT_HEAD (&s->cap_head, cap, entries);
        QLIST_INSERT_HEAD (&cap->cb_head, cb, entries);

        QLIST_FOREACH(hw, &glob_audio_state.hw_head_out, entries) {
            audio_attach_capture (hw);
        }
        return cap;

    err3:
        g_free (cap->hw.mix_buf);
    err2:
        g_free (cap);
    err1:
        g_free (cb);
    err0:
        return NULL;
    }
}

void AUD_del_capture (CaptureVoiceOut *cap, void *cb_opaque)
{
    struct capture_callback *cb;

    for (cb = cap->cb_head.lh_first; cb; cb = cb->entries.le_next) {
        if (cb->opaque == cb_opaque) {
            cb->ops.destroy (cb_opaque);
            QLIST_REMOVE (cb, entries);
            g_free (cb);

            if (!cap->cb_head.lh_first) {
                SWVoiceOut *sw = cap->hw.sw_head.lh_first, *sw1;

                while (sw) {
                    SWVoiceCap *sc = (SWVoiceCap *) sw;
#ifdef DEBUG_CAPTURE
                    dolog ("freeing %s\n", sw->name);
#endif

                    sw1 = sw->entries.le_next;
                    if (sw->rate) {
                        st_rate_stop (sw->rate);
                        sw->rate = NULL;
                    }
                    QLIST_REMOVE (sw, entries);
                    QLIST_REMOVE (sc, entries);
                    g_free (sc);
                    sw = sw1;
                }
                QLIST_REMOVE (cap, entries);
                g_free (cap->hw.mix_buf);
                g_free (cap->buf);
                g_free (cap);
            }
            return;
        }
    }
}

void AUD_set_volume_out (SWVoiceOut *sw, int mute, uint8_t lvol, uint8_t rvol)
{
    if (sw) {
        HWVoiceOut *hw = sw->hw;

        sw->vol.mute = mute;
        sw->vol.l = nominal_volume.l * lvol / 255;
        sw->vol.r = nominal_volume.r * rvol / 255;

        if (hw->pcm_ops->ctl_out) {
            hw->pcm_ops->ctl_out (hw, VOICE_VOLUME, sw);
        }
    }
}

void AUD_set_volume_in (SWVoiceIn *sw, int mute, uint8_t lvol, uint8_t rvol)
{
    if (sw) {
        HWVoiceIn *hw = sw->hw;

        sw->vol.mute = mute;
        sw->vol.l = nominal_volume.l * lvol / 255;
        sw->vol.r = nominal_volume.r * rvol / 255;

        if (hw->pcm_ops->ctl_in) {
            hw->pcm_ops->ctl_in (hw, VOICE_VOLUME, sw);
        }
    }
}
