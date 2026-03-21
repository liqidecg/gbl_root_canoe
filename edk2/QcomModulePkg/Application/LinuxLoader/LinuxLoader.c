/*
 * Copyright (c) 2009, Google Inc.
 * All rights reserved.
 *
 * Copyright (c) 2009-2021, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of The Linux Foundation nor
 *       the names of its contributors may be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 *  Changes from Qualcomm Innovation Center are provided under the following license:
 *
 *  Copyright (c) 2022 - 2025 Qualcomm Innovation Center, Inc. All rights
 *  reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted (subject to the limitations in the
 *  disclaimer below) provided that the following conditions are met:
 *
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *
 *      * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 *  NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 *  GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 *  HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 *  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "AutoGen.h"
#include "BootStats.h"
#include "KeyPad.h"
#include "LinuxLoaderLib.h"
#include <FastbootLib/FastbootMain.h>
#include <Library/DeviceInfo.h>
#include <Library/DrawUI.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PartitionTableUpdate.h>
#include <Library/ShutdownServices.h>
#include <Library/StackCanary.h>
#include "Library/ThreadStack.h"
#include <Library/HypervisorMvCalls.h>
#include <Library/UpdateCmdLine.h>
#include <Protocol/EFICardInfo.h>

#define MAX_APP_STR_LEN 64
#define MAX_NUM_FS 10
#define DEFAULT_STACK_CHK_GUARD 0xc0c0c0c0

#if HIBERNATION_SUPPORT_NO_AES
VOID BootIntoHibernationImage (BootInfo *Info,
                               BOOLEAN *SetRotAndBootStateAndVBH);
#endif

STATIC BOOLEAN BootIntoFastboot = FALSE;
STATIC BOOLEAN BootIntoRecovery = FALSE;
UINT64 FlashlessBootImageAddr = 0;
STATIC DeviceInfo DevInfo;


STATIC VOID
SetDefaultAudioFw ()
{
  CHAR8 AudioFW[MAX_AUDIO_FW_LENGTH];
  STATIC CHAR8* Src;
  STATIC CHAR8* AUDIOFRAMEWORK;
  STATIC UINT32 Length;
  EFI_STATUS Status;

  AUDIOFRAMEWORK = GetAudioFw ();
  Status = ReadAudioFrameWork (&Src, &Length);
  if ((AsciiStrCmp (Src, "audioreach") == 0) ||
                              (AsciiStrCmp (Src, "elite") == 0) ||
                              (AsciiStrCmp (Src, "awe") == 0)) {
    if (Status == EFI_SUCCESS) {
      if (AsciiStrLen (Src) == 0) {
        if (AsciiStrLen (AUDIOFRAMEWORK) > 0) {
          AsciiStrnCpyS (AudioFW, MAX_AUDIO_FW_LENGTH, AUDIOFRAMEWORK,
          AsciiStrLen (AUDIOFRAMEWORK));
          StoreAudioFrameWork (AudioFW, AsciiStrLen (AUDIOFRAMEWORK));
        }
      }
    }
    else {
      DEBUG ((EFI_D_ERROR, "AUDIOFRAMEWORK is NOT updated length =%d, %a\n",
      Length, AUDIOFRAMEWORK));
    }
  }
  else {
    if (Src != NULL) {
      Status =
      ReadWriteDeviceInfo (READ_CONFIG, (VOID *)&DevInfo, sizeof (DevInfo));
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR, "Unable to Read Device Info: %r\n", Status));
       }
      gBS->SetMem (DevInfo.AudioFramework, sizeof (DevInfo.AudioFramework), 0);
      gBS->CopyMem (DevInfo.AudioFramework, AUDIOFRAMEWORK,
                                      AsciiStrLen (AUDIOFRAMEWORK));
      Status =
      ReadWriteDeviceInfo (WRITE_CONFIG, (VOID *)&DevInfo, sizeof (DevInfo));
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR, "Unable to store audio framework: %r\n", Status));
        return;
      }
    }
  }
}

BOOLEAN IsABRetryCountUpdateRequired (VOID)
{
 BOOLEAN BatteryStatus;

 /* Check power off charging */
 TargetPauseForBatteryCharge (&BatteryStatus);

 /* Do not decrement bootable retry count in below states:
 * fastboot, fastbootd, charger, recovery
 */
 if ((BatteryStatus &&
 IsChargingScreenEnable ()) ||
 BootIntoFastboot ||
 BootIntoRecovery) {
  return FALSE;
 }
  return TRUE;
}


/**
  Linux Loader Application EntryPoint

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

 **/
/**
 * 等待指定时间内检测音量下键
 * 使用 WaitForEvent 避免轮询，更高效
 *
 * @param TimeoutMs超时时间（毫秒）
 * @return TRUE       检测到音量下键
 * @return FALSE      超时未检测到
 */
STATIC UINT8
WaitForVolumeDownKey (IN UINT32 TimeoutMs)
{
  EFI_STATUS    Status;
  EFI_EVENT     TimerEvent;
  EFI_EVENT     WaitList[2];
  UINTN         EventIndex;
  EFI_INPUT_KEY Key;
  UINT8         KeyDetected = 0;

  /* 先清空输入缓冲区 */
  gST->ConIn->Reset (gST->ConIn, FALSE);

  /* 创建定时器事件 */
  Status = gBS->CreateEvent (
                  EVT_TIMER,
                  TPL_CALLBACK,
                  NULL,
                  NULL,
                  &TimerEvent
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "CreateEvent Timer failed: %r\n", Status));
    return FALSE;
  }

  /* 设置定时器：一次性触发，单位为100ns
   * 5秒 = 5 * 1000 * 1000 * 10= 50,000,000 (100ns单位)
   */
  Status = gBS->SetTimer (
                  TimerEvent,
                  TimerRelative,
                  (UINT64)TimeoutMs * 10000   /* ms ->100ns */
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "SetTimer failed: %r\n", Status));
    gBS->CloseEvent (TimerEvent);
    return FALSE;
  }

  /* 等待事件列表：按键事件 或 定时器超时 */
  WaitList[0] = gST->ConIn->WaitForKey;
  WaitList[1] = TimerEvent;

  while (TRUE) {
    Status = gBS->WaitForEvent (2, WaitList, &EventIndex);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "WaitForEvent failed: %r\n", Status));
      break;
    }

    if (EventIndex == 0) {
      /* 按键事件触发 */
      Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
      if (!EFI_ERROR (Status)) {
        DEBUG ((EFI_D_INFO, "Key detected: ScanCode=0x%x, UnicodeChar=0x%x\n",Key.ScanCode, Key.UnicodeChar));

        if (Key.ScanCode == SCAN_DOWN) {//fastboot key
          /* 检测到音量下键 */
          KeyDetected = 1;
          break;
        }
        if (Key.ScanCode == SCAN_UP) { //recovery key
          /* 检测到音量上键*/
          KeyDetected = 2;
          break;
        }
        /* 不是目标按键，继续等待 */
        DEBUG ((EFI_D_INFO, "Not volume down key, continue waiting...\n"));
      }
    } else {
      /* 定时器超时 */
      DEBUG ((EFI_D_INFO, "Timeout: %d ms expired, no key pressed\n", TimeoutMs));
      break;
    }
  }

  /* 清理定时器事件 */
  gBS->CloseEvent (TimerEvent);

  return KeyDetected;
}
#include "ABL.h"
STATIC EFI_STATUS
BootEfiImage (VOID *Data, UINT32 Size)
{
  EFI_STATUS  Status;
  EFI_HANDLE  ImageHandle = NULL;

  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  NULL,
                  Data,
                  Size,
                  &ImageHandle
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "LoadImage failed: %r\n", Status));
    return Status;
  }

  Status = gBS->StartImage (ImageHandle, NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "StartImage failed: %r\n", Status));
  }

  return Status;
}
STATIC VOID LoadIntegratedEfi(VOID){
    BootEfiImage(dist_ABL_efi,dist_ABL_efi_len);
}
EFI_STATUS
ReadAllowUnlockValue (UINT32 *IsAllowUnlock);
EFI_STATUS EFIAPI  __attribute__ ( (no_sanitize ("safe-stack")))
LinuxLoaderEntry (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{

  EFI_STATUS Status;
  UINT32 IsAllowUnlock = FALSE;

   /* Update stack check guard with random value for better security */
  /* SilentMode Boot */
  /* MultiSlot Boot */
  /* Flashless Boot */
  EFI_MEM_CARDINFO_PROTOCOL *CardInfo = NULL;
  /* set ROT, BootState and VBH only once per boot*/

  /* RED = entry point reached */

  DEBUG ((EFI_D_INFO, "Loader Build Info: %a %a\n", __DATE__, __TIME__));
  DEBUG ((EFI_D_VERBOSE, "LinuxLoader Load Address to debug ABL: 0x%llx\n",
         (UINTN)LinuxLoaderEntry & (~ (0xFFF))));
  DEBUG ((EFI_D_VERBOSE, "LinuxLoaderEntry Address: 0x%llx\n",
         (UINTN)LinuxLoaderEntry));

  Status = InitThreadUnsafeStack ();

  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Unable to Allocate memory for Unsafe Stack: %r\n",
            Status));
    goto stack_guard_update_default;
  }


  /* Check if memory card is present; goto flashless if not */
  Status = gBS->LocateProtocol (&gEfiMemCardInfoProtocolGuid, NULL,
                                  (VOID **)&CardInfo);

  // Initialize verified boot & Read Device Info
  Status = DeviceInfoInit ();
  if (Status != EFI_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "Initialize the device info failed: %r\n", Status));
    goto stack_guard_update_default;
  }

  Status = EnumeratePartitions ();

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "LinuxLoader: Could not enumerate partitions: %r\n",
            Status));
    goto stack_guard_update_default;
  }


  UpdatePartitionEntries ();
  /*Check for multislot boot support*/
    Status = ReadAllowUnlockValue (&IsAllowUnlock);
  if (Status != EFI_SUCCESS|| !IsAllowUnlock) {
    DEBUG ((EFI_D_ERROR, "Unable to read allow unlock value: %r\n", Status));
    LoadIntegratedEfi();
    return EFI_SUCCESS;
  }

  //wait for 5 sec for key press
  Print(L"Press Volume Down key to enter Fastboot mode, waiting for 5 seconds into Normal mode...\n");
  Print(L"Press Volume Up key to enter Normal mode\n");
  INT8 KeyStatus = WaitForVolumeDownKey (5000);
  if(KeyStatus == 1) {
    Print(L"Volume Down key detected, entering Fastboot mode...\n");
  } else {
    DEBUG ((EFI_D_INFO, "No key detected, proceeding with normal boot...\n"));
    LoadIntegratedEfi();
    return EFI_SUCCESS;
   }
  FindPtnActiveSlot ();
  

  BootIntoFastboot = TRUE;

  SetDefaultAudioFw ();


#ifdef AUTO_VIRT_ABL
  DEBUG ((EFI_D_INFO, "Rebooting the device.\n"));
  RebootDevice (NORMAL_MODE);
#endif
  DEBUG ((EFI_D_INFO, "Launching fastboot\n"));
  Status = FastbootInitialize ();
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to Launch Fastboot App: %d\n", Status));
    goto stack_guard_update_default;
  }

stack_guard_update_default:
  /*Update stack check guard with defualt value then return*/
  __stack_chk_guard = DEFAULT_STACK_CHK_GUARD;

  DeInitThreadUnsafeStack ();

  return Status;
}
