/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "kodi/libXBMC_addon.h"
#include "kodi/threads/mutex.h"
#include <sstream>
#include <string>

ADDON::CHelper_libXBMC_addon *XBMC           = NULL;

extern "C" {

#include "hdhomerun.h"
#include "kodi/kodi_vfs_dll.h"
#include "kodi/IFileTypes.h"

//-- Create -------------------------------------------------------------------
// Called on load. Addon should fully initalize or return error status
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_Create(void* hdl, void* props)
{
  if (!XBMC)
    XBMC = new ADDON::CHelper_libXBMC_addon;

  if (!XBMC->RegisterMe(hdl))
  {
    delete XBMC, XBMC=NULL;
    return ADDON_STATUS_PERMANENT_FAILURE;
  }

  return ADDON_STATUS_OK;
}

//-- Stop ---------------------------------------------------------------------
// This dll must cease all runtime activities
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Stop()
{
}

//-- Destroy ------------------------------------------------------------------
// Do everything before unload of this add-on
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Destroy()
{
  XBMC=NULL;
}

//-- HasSettings --------------------------------------------------------------
// Returns true if this add-on use settings
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
bool ADDON_HasSettings()
{
  return false;
}

//-- GetStatus ---------------------------------------------------------------
// Returns the current Status of this visualisation
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_GetStatus()
{
  return ADDON_STATUS_OK;
}

//-- GetSettings --------------------------------------------------------------
// Return the settings for XBMC to display
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
unsigned int ADDON_GetSettings(ADDON_StructSetting ***sSet)
{
  return 0;
}

//-- FreeSettings --------------------------------------------------------------
// Free the settings struct passed from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------

void ADDON_FreeSettings()
{
}

//-- SetSetting ---------------------------------------------------------------
// Set a specific Setting value (called from XBMC)
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_SetSetting(const char *strSetting, const void* value)
{
  return ADDON_STATUS_OK;
}

//-- Announce -----------------------------------------------------------------
// Receive announcements from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Announce(const char *flag, const char *sender, const char *message, const void *data)
{
}

struct HDHContext
{
  struct hdhomerun_device_t* device;
};

static void Tokenize(const std::string& input, std::vector<std::string>& tokens, const std::string& delimiters)
{
  // Tokenize ripped from http://www.linuxselfhelp.com/HOWTO/C++Programming-HOWTO-7.html
  // Skip delimiters at beginning.
  std::string::size_type lastPos = input.find_first_not_of(delimiters, 0);
  // Find first "non-delimiter".
  std::string::size_type pos = input.find_first_of(delimiters, lastPos);

  while (std::string::npos != pos || std::string::npos != lastPos)
  {
    // Found a token, add it to the vector.
    tokens.push_back(input.substr(lastPos, pos - lastPos));
    // Skip delimiters.  Note the "not_of"
    lastPos = input.find_first_not_of(delimiters, pos);
    // Find next "non-delimiter"
    pos = input.find_first_of(delimiters, lastPos);
  }
}

void* Open(VFSURL* url)
{
  HDHContext* result = new HDHContext;

  result->device = hdhomerun_device_create_from_str(url->hostname, NULL);
  if(!result->device)
  {
    delete result;
    return NULL;
  }

  hdhomerun_device_set_tuner_from_str(result->device, url->filename);

  std::vector<std::string> opts;
  if (*url->options == '?')
    url->options++;
  
  Tokenize(url->options, opts, "&");
  for (size_t i=0;i<opts.size();++i)
  {
    size_t pos;
    if((pos=opts[i].find("channel=") != std::string::npos))
      hdhomerun_device_set_tuner_channel(result->device, opts[i].substr(7).c_str());

    if((pos=opts[i].find("program=") != std::string::npos))
      hdhomerun_device_set_tuner_program(result->device, opts[i].substr(8).c_str());
  }

  // start streaming from selected device and tuner
  if (hdhomerun_device_stream_start(result->device) <= 0)
  {
    hdhomerun_device_destroy(result->device);
    delete result;
    return NULL;
  } 

  return result;
}

bool Close(void* context)
{
  HDHContext* ctx = (HDHContext*)context;
  hdhomerun_device_stream_stop(ctx->device);
  hdhomerun_device_destroy(ctx->device);
  delete ctx;

  return true;
}

int64_t GetLength(void* context)
{
  return 0;
}

int64_t GetPosition(void* context)
{
  return 0;
}

int64_t Seek(void* context, int64_t iFilePosition, int iWhence)
{
  return -1;
}

bool Exists(VFSURL* url)
{
  /*
   *    * HDHomeRun URLs are of the form hdhomerun://1014F6D1/tuner0?channel=qam:108&program=10
   *    * The filename starts with "tuner" and has no extension. This check will cover off requests
   *    * for *.tbn, *.jpg, *.jpeg, *.edl etc. that do not exist.
   **/
  return strncmp(url->filename, "tuner", 6) == 0 && !strstr(url->filename,".");
}

int Stat(VFSURL* url, struct __stat64* buffer)
{
  memset(buffer, 0, sizeof(struct __stat64));
  return 0;
}

int IoControl(void* context, XFILE::EIoControl request, void* param)
{
  return -1;
}

void ClearOutIdle()
{
}

void DisconnectAll()
{
}

bool DirectoryExists(VFSURL* url)
{
  return false;
}

void* GetDirectory(VFSURL* url, VFSDirEntry** items,
                   int* num_items, VFSCallbacks* callbacks)
{
  if(strlen(url->hostname) == 0)
  {
    // no hostname, list all available devices
    int target_ip = 0;
    struct hdhomerun_discover_device_t result_list[64];
    int count = hdhomerun_discover_find_devices_custom(target_ip, HDHOMERUN_DEVICE_TYPE_TUNER, HDHOMERUN_DEVICE_ID_WILDCARD, result_list, 64);
    if (count < 0)
      return NULL;
    
    std::vector<VFSDirEntry>* result = new std::vector<VFSDirEntry>(2*count);
    std::vector<VFSDirEntry>& itms = *result;
    for(int i=0;i<count;i++)
    {
      unsigned int ip_addr = result_list[i].ip_addr;

      char device[16];
      sprintf(device, "%x", result_list[i].device_id);
      char ip[128];
      sprintf(ip, "%u.%u.%u.%u", 
              (unsigned int)(ip_addr >> 24) & 0xFF, (unsigned int)(ip_addr >> 16) & 0xFF,
              (unsigned int)(ip_addr >> 8) & 0xFF, (unsigned int)(ip_addr >> 0) & 0xFF);

      for (int j=0;j<2;++j)
      {
        itms[2*i+j].label = strdup((std::string(device) + "-"+(j?"1":"0") + "On " + ip).c_str());
        itms[2*i+j].folder = true;
        itms[2*i+j].path = strdup((std::string("hdhomerun://") + device + "/tuner"+(j?"1":"0")+"/").c_str());
        itms[2*i+j].num_props = 1;
        itms[2*i+j].properties = new VFSProperty;
        itms[2*i+j].properties->name = strdup("propmisusepreformatted");
        itms[2*i+j].properties->val = strdup("true");
      }
    }
    if (!result->empty())
      *items = &(*result)[0];
    *num_items = result->size();
    return result;
  }
  else
  {
    hdhomerun_device_t* device = hdhomerun_device_create_from_str(url->hostname, NULL);
    if(!device)
      return NULL;

    hdhomerun_device_set_tuner_from_str(device, url->filename);

    hdhomerun_tuner_status_t status;
    if(!hdhomerun_device_get_tuner_status(device, NULL, &status))
    {
      hdhomerun_device_destroy(device);
      return NULL;
    }

    std::string label;
    if(status.signal_present)
      label = "Current Stream: N/A";
    else
    {
      label.reserve(128);
      sprintf(&label[0], "Current Stream: Channel %s, SNR %d", status.channel, status.signal_to_noise_quality);
    }

    std::string path = std::string("hdhomerun://") + url->hostname + "/" + url->filename;
    if (path[path.size()-1] == '/')
      path.erase(path.end()-1);
    std::vector<VFSDirEntry>* result = new std::vector<VFSDirEntry>(1);
    std::vector<VFSDirEntry>& itms = *result;
    itms[0].label = strdup(label.c_str());
    itms[0].folder = false;
    itms[0].path = strdup(path.c_str());
    itms[0].num_props = 1;
    itms[0].properties = new VFSProperty;
    itms[0].properties->name = strdup("propmisusepreformatted");
    itms[0].properties->val = strdup("true");
    hdhomerun_device_destroy(device);
    *items = &(*result)[0];
    *num_items = 1;
    return result;
  }

  return NULL;
}

void FreeDirectory(void* items)
{
  std::vector<VFSDirEntry>& ctx = *(std::vector<VFSDirEntry>*)items;
  for (size_t i=0;i<ctx.size();++i)
  {
    free(ctx[i].label);
    for (size_t j=0;j<ctx[i].num_props;++j)
    {
      free(ctx[i].properties[j].name);
      free(ctx[i].properties[j].val);
    }
    delete[] ctx[i].properties;
    free(ctx[i].path);
  }
  delete &ctx;
}

bool CreateDirectory(VFSURL* url)
{
  return false;
}

bool RemoveDirectory(VFSURL* url)
{
  return false;
}

int Truncate(void* context, int64_t size)
{
  return -1;
}

ssize_t Read(void* context, void* lpBuf, size_t uiBufSize)
{
  HDHContext* ctx = (HDHContext*)context;

  size_t datasize;

  if (uiBufSize < VIDEO_DATA_PACKET_SIZE)
    XBMC->Log(ADDON::LOG_ERROR, "CHomeRunFile::Read - buffer size too small, will most likely fail");

  // for now, let it it time out after 5 seconds,
  // neither of the players can be forced to
  // continue even if read return 0 as can happen
  // on live streams.
  PLATFORM::CTimeout timestamp(5000);
  while(1)
  {
    datasize = uiBufSize;
    uint8_t* ptr = hdhomerun_device_stream_recv(ctx->device, datasize, &datasize);
    if(ptr)
    {
      memcpy(lpBuf, ptr, datasize);
      return datasize;
    }

    if(timestamp.TimeLeft() == 0)
      return 0;

    PLATFORM::CEvent::Sleep(64);
  }
  return datasize;
}

ssize_t Write(void* context, const void* lpBuf, size_t uiBufSize)
{
  return -1;
}

bool Delete(VFSURL* url)
{
  return false;
}

bool Rename(VFSURL* url, VFSURL* url2)
{
  return false;
}

void* OpenForWrite(VFSURL* url, bool bOverWrite)
{
  return NULL;
}

void* ContainsFiles(VFSURL* url, VFSDirEntry** items, int* num_items, char* rootpath)
{
  return NULL;
}

int GetChunkSize(void* context)
{
  return VIDEO_DATA_PACKET_SIZE;
}

}
