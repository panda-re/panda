/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
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
 * @file NativeLibraryWhitelist.h
 *   Creates a list of known native libraries for the Android system.
 * @author Lok Yan
 * @date 5 Jan 2012
 */

#ifndef NATIVE_LIBRARY_WHITELIST_H
#define NATIVE_LIBRARY_WHITELIST_H

#include "utils/StringHashtable.h"

static void NativeLibraryWhitelist_free(StringHashtable* pTable)
{
  StringHashtable_free(pTable);
}

static StringHashtable* NativeLibraryWhitelist_new()
{
  StringHashtable* pTable = StringHashtable_new();
  if (pTable == NULL)
  {
    return (pTable);
  }

  StringHashtable_add(pTable, "/lib/egl/libGLES_android.so");
  StringHashtable_add(pTable, "/lib/hw/gps.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/gralloc.default.so");
  StringHashtable_add(pTable, "/lib/hw/sensors.goldfish.so");
  StringHashtable_add(pTable, "/lib/invoke_mock_media_player.so");
  StringHashtable_add(pTable, "/lib/libacc.so");
  StringHashtable_add(pTable, "/lib/libandroid_runtime.so");
  StringHashtable_add(pTable, "/lib/libandroid_servers.so");
  StringHashtable_add(pTable, "/lib/libandroid.so");
  StringHashtable_add(pTable, "/lib/libaudioeffect_jni.so");
  StringHashtable_add(pTable, "/lib/libaudioflinger.so");
  StringHashtable_add(pTable, "/lib/libbinder.so");
  StringHashtable_add(pTable, "/lib/libcamera_client.so");
  StringHashtable_add(pTable, "/lib/libcameraservice.so");
  StringHashtable_add(pTable, "/lib/libc_malloc_debug_leak.so");
  StringHashtable_add(pTable, "/lib/libc_malloc_debug_qemu.so");
  StringHashtable_add(pTable, "/lib/libcrypto.so");
  StringHashtable_add(pTable, "/lib/libc.so");
  StringHashtable_add(pTable, "/lib/libctest.so");
  StringHashtable_add(pTable, "/lib/libcutils.so");
  StringHashtable_add(pTable, "/lib/libdbus.so");
  StringHashtable_add(pTable, "/lib/libdiskconfig.so");
  StringHashtable_add(pTable, "/lib/libdl.so");
  StringHashtable_add(pTable, "/lib/libdrm1_jni.so");
  StringHashtable_add(pTable, "/lib/libdrm1.so");
  StringHashtable_add(pTable, "/lib/libdvm.so");
  StringHashtable_add(pTable, "/lib/libeffects.so");
  StringHashtable_add(pTable, "/lib/libEGL.so");
  StringHashtable_add(pTable, "/lib/libemoji.so");
  StringHashtable_add(pTable, "/lib/libETC1.so");
  StringHashtable_add(pTable, "/lib/libexif.so");
  StringHashtable_add(pTable, "/lib/libexpat.so");
  StringHashtable_add(pTable, "/lib/libFFTEm.so");
  StringHashtable_add(pTable, "/lib/libGLESv1_CM.so");
  StringHashtable_add(pTable, "/lib/libGLESv2.so");
  StringHashtable_add(pTable, "/lib/libgui.so");
  StringHashtable_add(pTable, "/lib/libhardware_legacy.so");
  StringHashtable_add(pTable, "/lib/libhardware.so");
  StringHashtable_add(pTable, "/lib/libicui18n.so");
  StringHashtable_add(pTable, "/lib/libicuuc.so");
  StringHashtable_add(pTable, "/lib/libiprouteutil.so");
  StringHashtable_add(pTable, "/lib/libjnigraphics.so");
  StringHashtable_add(pTable, "/lib/libjni_latinime.so");
  StringHashtable_add(pTable, "/lib/libjni_pinyinime.so");
  StringHashtable_add(pTable, "/lib/libjpeg.so");
  StringHashtable_add(pTable, "/lib/liblog.so");
  StringHashtable_add(pTable, "/lib/libmedia_jni.so");
  StringHashtable_add(pTable, "/lib/libmediaplayerservice.so");
  StringHashtable_add(pTable, "/lib/libmedia.so");
  StringHashtable_add(pTable, "/lib/libmock_ril.so");
  StringHashtable_add(pTable, "/lib/libm.so");
  StringHashtable_add(pTable, "/lib/libnativehelper.so");
  StringHashtable_add(pTable, "/lib/libnetlink.so");
  StringHashtable_add(pTable, "/lib/libnetutils.so");
  StringHashtable_add(pTable, "/lib/libnfc_ndef.so");
  StringHashtable_add(pTable, "/lib/libOpenSLES.so");
  StringHashtable_add(pTable, "/lib/libpagemap.so");
  StringHashtable_add(pTable, "/lib/libpixelflinger.so");
  StringHashtable_add(pTable, "/lib/libreference-cdma-sms.so");
  StringHashtable_add(pTable, "/lib/libreference-ril.so");
  StringHashtable_add(pTable, "/lib/libril.so");
  StringHashtable_add(pTable, "/lib/librtp_jni.so");
  StringHashtable_add(pTable, "/lib/libsensorservice.so");
  StringHashtable_add(pTable, "/lib/libskiagl.so");
  StringHashtable_add(pTable, "/lib/libskia.so");
  StringHashtable_add(pTable, "/lib/libsonivox.so");
  StringHashtable_add(pTable, "/lib/libsoundpool.so");
  StringHashtable_add(pTable, "/lib/libsqlite_jni.so");
  StringHashtable_add(pTable, "/lib/libsqlite.so");
  StringHashtable_add(pTable, "/lib/libSR_AudioIn.so");
  StringHashtable_add(pTable, "/lib/libsrec_jni.so");
  StringHashtable_add(pTable, "/lib/libssl.so");
  StringHashtable_add(pTable, "/lib/libstagefright_amrnb_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_avc_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_color_conversion.so");
  StringHashtable_add(pTable, "/lib/libstagefright_enc_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_foundation.so");
  StringHashtable_add(pTable, "/lib/libstagefright_omx.so");
  StringHashtable_add(pTable, "/lib/libstagefright.so");
  StringHashtable_add(pTable, "/lib/libstdc++.so");
  StringHashtable_add(pTable, "/lib/libstlport.so");
  StringHashtable_add(pTable, "/lib/libsurfaceflinger_client.so");
  StringHashtable_add(pTable, "/lib/libsurfaceflinger.so");
  StringHashtable_add(pTable, "/lib/libsystem_server.so");
  StringHashtable_add(pTable, "/lib/libsysutils.so");
  StringHashtable_add(pTable, "/lib/libterm.so");
  StringHashtable_add(pTable, "/lib/libthread_db.so");
  StringHashtable_add(pTable, "/lib/libttspico.so");
  StringHashtable_add(pTable, "/lib/libttssynthproxy.so");
  StringHashtable_add(pTable, "/lib/libui.so");
  StringHashtable_add(pTable, "/lib/libutils.so");
  StringHashtable_add(pTable, "/lib/libvorbisidec.so");
  StringHashtable_add(pTable, "/lib/libwebcore.so");
  StringHashtable_add(pTable, "/lib/libwpa_client.so");
  StringHashtable_add(pTable, "/lib/libz.so");
  StringHashtable_add(pTable, "/lib/soundfx/libbundlewrapper.so");
  StringHashtable_add(pTable, "/lib/soundfx/libreverbwrapper.so");
  StringHashtable_add(pTable, "/lib/soundfx/libvisualizer.so");

  return (pTable);
}

#endif//NATIVE_LIBRARY_WHITELIST_H
