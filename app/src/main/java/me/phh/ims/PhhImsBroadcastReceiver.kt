// SPDX-License-Identifier: GPL-2.0
package me.phh.ims

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.Rlog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.IOException

class PhhImsBroadcastReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "PHH ImsBroadcastReceiver"
    }

    val ALARM_PERIODIC_REGISTER = "me.phh.ims.ALARM_PERIODIC_REGISTER"

    override fun onReceive(
        ctxt: Context,
        intent: Intent,
    ) {
        Rlog.d(TAG, "Alarm fired with ${intent.action}")
        if (intent.action == ALARM_PERIODIC_REGISTER) {
            val imsService = PhhImsService.Companion.instance!!
            // rearm alarm
            imsService.armPeriodicRegisterAlarm()
            // XXX take some lock until this comes back?
            // (not function return, but callback after notify)
            CoroutineScope(Dispatchers.IO).launch {
                val sipHandler = imsService.mmTelFeature?.getSipHandlerOrNull()
                try {
                    sipHandler?.register()
                } catch (e: IOException) {
                    Rlog.w(TAG, "Periodic REGISTER failed (stale socket), reconnecting", e)
                    try {
                        sipHandler?.connect()
                    } catch (e2: Throwable) {
                        Rlog.e(TAG, "Reconnect after failed REGISTER also failed", e2)
                        sipHandler?.imsFailureCallback?.invoke()
                    }
                }
            }
            return
        }
    }
}
