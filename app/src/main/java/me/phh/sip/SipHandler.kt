// SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.annotation.SuppressLint
import android.content.Context
import android.media.*
import android.net.*
import android.os.Handler
import android.os.HandlerThread
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.PhoneNumberUtils
import android.telephony.Rlog
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.*
import java.net.*
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

private data class smsHeaders(
    val dest: String,
    val callId: String,
    val cseq: String,
)

class SipHandler(
    val ctxt: Context,
) {
    companion object {
        private const val TAG = "PHH SipHandler"
    }

    val myHandler = Handler(HandlerThread("PhhMmTelFeature").apply { start() }.looper)
    val myExecutor = Executor { p0 -> myHandler.post(p0) }

    private val subscriptionManager: SubscriptionManager
    private val telephonyManager: TelephonyManager
    private val connectivityManager: ConnectivityManager
    private val ipSecManager: IpSecManager

    init {
        subscriptionManager = ctxt.getSystemService(SubscriptionManager::class.java)
        telephonyManager = ctxt.getSystemService(TelephonyManager::class.java)
        connectivityManager = ctxt.getSystemService(ConnectivityManager::class.java)
        ipSecManager = ctxt.getSystemService(IpSecManager::class.java)
    }

    @SuppressLint("MissingPermission")
    private val activeSubscription = subscriptionManager.activeSubscriptionInfoList!![0]
    private val imei = telephonyManager.getDeviceId(activeSubscription.simSlotIndex)
    private val subId = activeSubscription.subscriptionId
    private val mcc = telephonyManager.simOperator.substring(0 until 3)
    private var mnc =
        telephonyManager.simOperator.substring(3).let { if (it.length == 2) "0$it" else it }
    private val imsi = telephonyManager.subscriberId

    /* Carrier specific settings
     */
    val isControlSocketUdp =
        when (mcc + mnc) {
            "450006" -> true

            // LG U+ can only do UDP
            "208010" -> true

            // 20810 can do TCP and UDP. use this for testing
            else -> false
        }
    val forceSmsc =
        when (mcc + mnc) {
            "450006" -> "821080010585"

            // LG U+
            else -> null
        }

    // Sess is more secure so default to it
    val requireNonsessAka =
        when (mcc + mnc) {
            "450006" -> true
            else -> false
        }

    // private val realm = "ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
    private val realm = "ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
    private val user = "$imsi@$realm"
    private var akaDigest =
        """Digest username="$user",realm="$realm",nonce="",uri="sip:$realm",response="",algorithm=AKAv1-MD5"""

    fun generateCallId(): SipHeadersMap {
        val callId = randomBytes(12).toHex()
        return mapOf("call-id" to listOf(callId))
    }

    private var registerCounter = 1
    private var registerHeaders =
        """
        From: <sip:$user>
        To: <sip:$user>
        """.toSipHeadersMap() + generateCallId()
    private var commonHeaders = "".toSipHeadersMap()
    private var contact = ""
    private var mySip = ""
    private var myTel = ""

    // too many lateinit, bad separation?
    private lateinit var localAddr: InetAddress
    private lateinit var pcscfAddr: InetAddress

    data class SipIpsecSettings(
        val clientSpiC: IpSecManager.SecurityParameterIndex,
        val clientSpiS: IpSecManager.SecurityParameterIndex,
        val serverSpiC: IpSecManager.SecurityParameterIndex? = null,
        val serverSpiS: IpSecManager.SecurityParameterIndex? = null,
    )

    lateinit var ipsecSettings: SipIpsecSettings

    private lateinit var network: Network

    private lateinit var plainSocket: SipConnection
    private lateinit var socket: SipConnection
    private lateinit var serverSocket: SipConnectionTcpServer
    private lateinit var serverSocketUdp: SipConnectionUdpServer
    private var reliableSequenceCounter = 67

    private val cbLock = ReentrantLock()
    private var requestCallbacks: Map<SipMethod, ((SipRequest) -> Int)> = mapOf()
    private var responseCallbacks: Map<String, ((SipResponse) -> Boolean)> = mapOf()
    private var imsReady = false
    var imsReadyCallback: (() -> Unit)? = null
    var imsFailureCallback: (() -> Unit)? = null
    var onSmsReceived: ((Int, String, ByteArray) -> Unit)? = null
    var onSmsStatusReportReceived: ((Int, String, ByteArray) -> Unit)? = null
    var onIncomingCall: ((handle: Object, from: String, extras: Map<String, String>) -> Unit)? =
        null
    var onOutgoingCallConnected: ((handle: Object, extras: Map<String, String>) -> Unit)? =
        null
    var onCancelledCall: ((handle: Object, from: String, extras: Map<String, String>) -> Unit)? =
        null
    private val smsLock = ReentrantLock()
    private var smsToken = 0
    private val smsHeadersMap = mutableMapOf<Int, smsHeaders>()

    fun setRequestCallback(
        method: SipMethod,
        cb: (SipRequest) -> Int,
    ) {
        cbLock.withLock { requestCallbacks += (method to cb) }
    }

    fun setResponseCallback(
        callId: String,
        cb: (SipResponse) -> Boolean,
    ) {
        cbLock.withLock { responseCallbacks += (callId to cb) }
    }

    fun parseMessage(
        reader: SipReader,
        writer: OutputStream,
    ): Boolean {
        val msg =
            try {
                reader.parseMessage()
            } catch (e: SocketException) {
                Rlog.d(TAG, "Got exception $e")
                if ("$e" == "java.net.SocketException: Try again") {
                    // we sometimes seem to get EAGAIN
                    return true
                }
                throw e
            }
        Rlog.d(TAG, "RObject() message $msg")
        if (msg is SipResponse) {
            return handleResponse(msg)
        }
        if (msg !is SipRequest) {
            // invalid message, stop trying
            Rlog.d(TAG, "Got invalid message! Closing socket (except main)")
            return false
        }

        val requestCb = cbLock.withLock { requestCallbacks[msg.method] }
        var status = 200
        // XXX default requestCb = notification?
        if (requestCb != null) {
            status = requestCb(msg)
        }
        if (status == 0) return true
        val reply =
            SipResponse(
                statusCode = status,
                statusString =
                    if (status == 200) {
                        "OK"
                    } else if (status == 100) {
                        "Trying"
                    } else {
                        "ERROR"
                    },
                headersParam =
                    msg.headers.filter { (k, _) ->
                        k in listOf("cseq", "via", "from", "to", "call-id")
                    },
            )
        Rlog.d(TAG, "Replying back with $reply")
        synchronized(writer) { writer.write(reply.toByteArray()) }

        return true
    }

    fun handleResponse(response: SipResponse): Boolean {
        val callId = response.headers["call-id"]?.get(0)
        if (callId == null) {
            // message without call-id should never happen, close connection
            return false
        }
        val responseCb = cbLock.withLock { responseCallbacks[callId] }
        if (responseCb == null) {
            // nothing to do
            return true
        }

        if (responseCb(response)) {
            // remove callback if done
            cbLock.withLock { responseCallbacks -= callId }
        }
        return true
    }

    var abandonnedBecauseOfNoPcscf = false

    fun connect() {
        abandonnedBecauseOfNoPcscf = false
        Rlog.d(TAG, "Trying to connect to SIP server")
        val lp = connectivityManager.getLinkProperties(network)
        Rlog.d(TAG, "Got link properties $lp")
        val pcscfs = (lp!!.javaClass.getMethod("getPcscfServers").invoke(lp) as List<*>).sortedBy { if (it is Inet6Address) 0 else 1 }
        val pcscf =
            if (pcscfs.isNotEmpty()) {
                pcscfs[0] as InetAddress
            } else {
                // RIL didn't provide P-CSCF via LinkProperties. Try standard 3GPP DNS discovery
                // (TS 23.003 §13.2): resolve the well-known IMS domain for this PLMN.
                // These are public DNS records so InetAddress.getByName() over any network works.
                // NOTE: future e164.arpa (ENUM) lookups must use network.getAllByName() instead,
                // as those records are only served by the carrier's IMS PDN DNS servers.
                val dnsFallback =
                    try {
                        InetAddress.getByName("ims.mnc$mnc.mcc$mcc.pub.3gppnetwork.org")
                    } catch (t: Throwable) {
                        null
                    }
                        ?: try {
                            InetAddress.getByName("ims.mnc$mnc.mcc$mcc.3gppnetwork.org")
                        } catch (t: Throwable) {
                            null
                        }
                        ?: android.os.SystemProperties
                            .get("persist.ims.pcscf_fallback", "")
                            .takeIf { it.isNotEmpty() }
                            ?.let {
                                try {
                                    InetAddress.getByName(it)
                                } catch (t: Throwable) {
                                    null
                                }
                            }
                if (dnsFallback != null) {
                    Rlog.w(TAG, "No P-CSCF from RIL, using fallback: $dnsFallback")
                    dnsFallback
                } else {
                    Rlog.w(TAG, "No P-CSCF and all fallbacks failed, waiting for onLinkPropertiesChanged")
                    abandonnedBecauseOfNoPcscf = true
                    return
                }
            }

        localAddr =
            lp.linkAddresses
                .map { it.address }
                .sortedBy { if (it is Inet6Address) 0 else 1 }
                .first()
        pcscfAddr = pcscf

        Rlog.w(TAG, "Connecting with address $localAddr to $pcscfAddr")

        val clientSpiC = ipSecManager.allocateSecurityParameterIndex(localAddr)
        val clientSpiS = ipSecManager.allocateSecurityParameterIndex(localAddr, clientSpiC.spi + 1)
        ipsecSettings =
            SipIpsecSettings(
                clientSpiS = clientSpiS,
                clientSpiC = clientSpiC,
            )

        plainSocket =
            if (isControlSocketUdp) {
                SipConnectionUdp(network, pcscfAddr, localAddr)
            } else {
                SipConnectionTcp(network, pcscfAddr, localAddr)
            }
        plainSocket.connect(5060)
        socket =
            if (plainSocket is SipConnectionTcp) {
                SipConnectionTcp(network, pcscfAddr, plainSocket.gLocalAddr())
            } else {
                SipConnectionUdp(network, pcscfAddr, plainSocket.gLocalAddr())
            }
        serverSocket =
            SipConnectionTcpServer(network, pcscfAddr, plainSocket.gLocalAddr(), socket.gLocalPort() + 1)
        serverSocketUdp =
            SipConnectionUdpServer(network, pcscfAddr, plainSocket.gLocalAddr(), socket.gLocalPort() + 1)

        Rlog.d(
            TAG,
            "Src port is ${socket.gLocalPort()}, TCP server port is ${serverSocket.localPort}, UDP server port is ${serverSocketUdp.localPort}",
        )
        updateCommonHeaders(plainSocket)
        register(plainSocket.gWriter())
        val plainRegReply =
            if (plainSocket is SipConnectionTcp) {
                plainSocket.gReader().parseMessage()
            } else {
                // In some IMS servers, in UDP send mode, message might come back to plainSocket or to serverSocketUdp
                if (select(listOf(serverSocketUdp.getChannel(), plainSocket.getChannel())) == 0) {
                    serverSocketUdp.gReader().parseMessage()
                } else {
                    plainSocket.gReader().parseMessage()
                }
            }
        Rlog.d(TAG, "Received $plainRegReply")
        plainSocket.close()
        if (plainRegReply !is SipResponse || plainRegReply.statusCode != 401) {
            Rlog.w(TAG, "Didn't get expected response from initial register, aborting")
            imsFailureCallback?.invoke()
            return
        }

        val (wwwAuthenticateType, wwwAuthenticateParams) =
            plainRegReply.headers["www-authenticate"]!![0].getAuthValues()
        require(wwwAuthenticateType == "Digest")
        val nonceB64 = wwwAuthenticateParams["nonce"]!!
        // Use the realm from the 401 challenge for H1 and the Authorization realm= field,
        // as required by RFC 2617. Carriers often differ from the subscriber's own realm.
        val challengeRealm = wwwAuthenticateParams["realm"] ?: realm

        Rlog.d(TAG, "Requesting AKA challenge")
        val akaResult = sipAkaChallenge(telephonyManager, nonceB64)
        // Use non-sess digest when server doesn't offer qop (no cnonce/nc in response).
        akaDigest =
            if (requireNonsessAka || wwwAuthenticateParams["qop"] == null) {
                SipAkaDigest(
                    user = user,
                    realm = challengeRealm,
                    uri = "sip:$realm",
                    nonceB64 = nonceB64,
                    opaque = wwwAuthenticateParams["opaque"],
                    akaResult = akaResult,
                ).toString()
            } else {
                SipAkaDigestSess(
                    user = user,
                    realm = challengeRealm,
                    uri = "sip:$realm",
                    nonceB64 = nonceB64,
                    opaque = wwwAuthenticateParams["opaque"],
                    akaResult = akaResult,
                ).toString()
            }

        var portS = 5060
        // Check if there is a security-server header in the reply
        if (plainRegReply.headers.containsKey("security-server")) {
            val securityServer = plainRegReply.headers["security-server"]!!
            commonHeaders += ("security-verify" to securityServer)
            registerHeaders += ("security-verify" to securityServer)
            val supported_alg = listOf("hmac-sha-1-96", "hmac-md5-96")
            val supported_ealg = listOf("aes-cbc", "null")
            val (securityServerType, securityServerParams) =
                securityServer
                    .map { it.getParams() }
                    .filter {
                        val thisEAlg = it.component2()["ealg"] ?: "null"
                        supported_ealg.contains(thisEAlg)
                    }.filter { supported_alg.contains(it.component2()["alg"]) }
                    .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
            require(securityServerType == "ipsec-3gpp")

            portS = securityServerParams["port-s"]!!.toInt()
            // spi string is 32 bit unsigned, but ipSecManager wants an int...
            val spiS = securityServerParams["spi-s"]!!.toUInt().toInt()
            val serverSpiS = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiS)

            val spiC = securityServerParams["spi-c"]!!.toUInt().toInt()
            val serverSpiC = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiC)

            ipsecSettings =
                SipIpsecSettings(
                    clientSpiS = clientSpiS,
                    clientSpiC = clientSpiC,
                    serverSpiC = serverSpiC,
                    serverSpiS = serverSpiS,
                )

            val ealg = securityServerParams["ealg"] ?: "null"
            val (alg, hmac_key) =
                if (securityServerParams["alg"] == "hmac-sha-1-96") {
                    // sha-1-96 mac key must be 160 bits, pad ik
                    IpSecAlgorithm.AUTH_HMAC_SHA1 to akaResult.ik + ByteArray(4)
                } else {
                    IpSecAlgorithm.AUTH_HMAC_MD5 to akaResult.ik
                }
            val ipSecBuilder =
                IpSecTransform
                    .Builder(ctxt)
                    .setAuthentication(IpSecAlgorithm(alg, hmac_key, 96))
                    .also {
                        if (ealg == "aes-cbc") {
                            it.setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck))
                        }
                    }

            val serverInTransform = ipSecBuilder.buildTransportModeTransform(pcscfAddr, clientSpiS)
            val serverOutTransform = ipSecBuilder.buildTransportModeTransform(localAddr, serverSpiC)
            socket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiC, serverSpiS)
            serverSocket.enableIpsec(ipSecManager, serverInTransform, serverOutTransform)
            serverSocketUdp.enableIpsec(ipSecManager, serverInTransform, serverOutTransform)
        }
        socket.connect(portS)
        updateCommonHeaders(socket)
        register()
        val regReply =
            (
                if (socket is SipConnectionTcp) {
                    socket.gReader()
                } else if (socket is SipConnectionUdp) {
                    serverSocketUdp.gReader()
                } else {
                    socket.gReader()
                }
            ).parseMessage()!!
        Rlog.d(TAG, "Received $regReply")

        if (regReply !is SipResponse || regReply.statusCode != 200) {
            Rlog.w(TAG, "Could not connect, aborting SIP")
            imsFailureCallback?.invoke()
            return
        }

        setResponseCallback(registerHeaders["call-id"]!![0], ::registerCallback)
        setRequestCallback(SipMethod.MESSAGE, ::handleSms)
        setRequestCallback(SipMethod.INVITE, ::handleCall)
        setRequestCallback(SipMethod.PRACK, ::handlePrack)
        setRequestCallback(SipMethod.CANCEL, ::handleCancel)
        setRequestCallback(SipMethod.BYE, ::handleCancel)
        setRequestCallback(SipMethod.UPDATE, ::handleUpdate)
        handleResponse(regReply)

        // two ways we'll get incoming messages:
        // - reply to normal socket (just read forever)
        // - connection to server socket
        // start both in threads as we're only called here from network
        // callback from which it's better to return
        CoroutineScope(Dispatchers.IO).launch {
            try {
                while (parseMessage(socket.gReader(), socket.gWriter())) { }
                Rlog.w(TAG, "Main socket got EOF, reconnecting")
            } catch (t: Throwable) {
                Rlog.w(TAG, "Got exception in main/control socket, reconnecting", t)
            }
            socket.close()
            try {
                connect()
            } catch (t: Throwable) {
                Rlog.e(TAG, "Reconnect after main socket loss failed", t)
                imsFailureCallback?.invoke()
            }
        }
        CoroutineScope(Dispatchers.IO).launch {
            try {
                while (true) {
                    // XXX catch and reconnect on 'java.net.SocketException: Socket closed' ?
                    val client = serverSocket.serverSocket.accept()
                    // there can only be a single client at a time because
                    // both source and destination ports are fixed
                    val reader = client.getInputStream().sipReader()
                    val writer = client.getOutputStream()
                    while (parseMessage(reader, writer)) { }
                    client.close()
                }
            } catch (t: Throwable) {
                Rlog.d(TAG, "Got exception in TCP server socket", t)
            }
        }
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val bufferIn = ByteArray(128 * 1024)
                val dgramPacketIn = DatagramPacket(bufferIn, bufferIn.size)
                val writer = ByteArrayOutputStream()
                while (true) {
                    dgramPacketIn.length = bufferIn.size
                    serverSocketUdp.socket.receive(dgramPacketIn)
                    Rlog.d(TAG, "Received dgram packet")
                    val baIs = ByteArrayInputStream(dgramPacketIn.data, dgramPacketIn.offset, dgramPacketIn.length)
                    val reader = baIs.sipReader()
                    while (parseMessage(reader, writer)) { }
                    val writerOut = writer.toByteArray()
                    val dgramPacketOut = DatagramPacket(writerOut, writerOut.size, dgramPacketIn.address, dgramPacketIn.port)
                    serverSocketUdp.socket.send(dgramPacketOut)
                    writer.reset()
                }
            } catch (t: Throwable) {
                Rlog.d(TAG, "Got exception in UDP server socket", t)
            }
        }
    }

    fun getVolteNetwork() {
        // TODO add something similar for VoWifi ipsec tunnel?
        Rlog.d(TAG, "Requesting IMS network")
        connectivityManager.requestNetwork(
            NetworkRequest
                .Builder()
                // .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                // .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                // .setNetworkSpecifier(subId.toString())
                .addCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
                // .addCapability(NetworkCapabilities.NET_CAPABILITY_MMTEL)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onUnavailable() {
                    Rlog.d(TAG, "IMS network unavailable")
                }

                override fun onLost(network: Network) {
                    Rlog.d(TAG, "IMS network lost")
                }

                override fun onBlockedStatusChanged(
                    network: Network,
                    blocked: Boolean,
                ) {
                    Rlog.d(TAG, "IMS network blocked status changed $blocked")
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) {
                    Rlog.d(TAG, "IMS network capabilities changed $networkCapabilities")
                }

                override fun onLosing(
                    network: Network,
                    maxMsToLive: Int,
                ) {
                    Rlog.d(TAG, "IMS network losing")
                }

                override fun onLinkPropertiesChanged(
                    _network: Network,
                    linkProperties: LinkProperties,
                ) {
                    Rlog.d(TAG, "IMS network link properties changed $linkProperties")
                    val pcscfs = linkProperties!!.javaClass.getMethod("getPcscfServers").invoke(linkProperties) as List<*>
                    Rlog.d(TAG, "Got pcscfs $pcscfs")
                    if (pcscfs.isNotEmpty() && abandonnedBecauseOfNoPcscf) {
                        // Switch to this network if it has P-CSCF (could be a different bearer)
                        network = _network
                        try {
                            connect()
                        } catch (e: Throwable) {
                            Rlog.e(TAG, "connect() from onLinkPropertiesChanged failed: $e")
                        }
                    }
                }

                override fun onAvailable(_network: Network) {
                    Rlog.d(TAG, "Got IMS network.")
                    if (!this@SipHandler::network.isInitialized || abandonnedBecauseOfNoPcscf) {
                        network = _network
                        thread {
                            Thread.sleep(4000)
                            try {
                                connect()
                            } catch (e: Throwable) {
                                Rlog.e(TAG, "connect() failed: $e")
                            }
                        }
                    } else {
                        Rlog.d(TAG, "... don't try anything")
                    }
                }
            },
        )
    }

    fun updateCommonHeaders(socket: SipConnection) {
        // Note: we are giving serverSocket (TCP) port, but TCP and UDP servers use the same port
        val local =
            if (socket.gLocalAddr() is Inet6Address) {
                "[${socket.gLocalAddr().hostAddress}]:${serverSocket.localPort}"
            } else {
                "${socket.gLocalAddr().hostAddress}:${serverSocket.localPort}"
            }

        val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
        val transport = if (socket is SipConnectionTcp) "tcp" else "udp"
        contact =
            """<sip:$imsi@$local;transport=$transport>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
        val newHeaders =
            (
                if (socket is SipConnectionTcp) {
                    """
                Via: SIP/2.0/TCP $local;rport
                """
                } else {
                    """
                Via: SIP/2.0/UDP $local;rport
                """
                }
            ).toSipHeadersMap()
        registerHeaders += newHeaders
        commonHeaders += newHeaders
    }

    @SuppressLint("MissingPermission")
    fun register(_writer: OutputStream? = null) {
        val tm = ctxt.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

        val cellInfoList = tm.getAllCellInfo()
        for (cell in cellInfoList) {
            if (cell is CellInfoLte) {
                val cellIdentity = cell.cellIdentity
                val cellSignalStrength = cell.cellSignalStrength
                Rlog.d(
                    TAG,
                    "LTE cell: ${cellIdentity.ci}, ${cellIdentity.pci}, ${cellIdentity.tac}, ${cellIdentity.mcc}, ${cellIdentity.mnc}, ${cellSignalStrength.dbm}",
                )
            } else if (cell is CellInfoNr) {
                val cellIdentity = cell.cellIdentity
                val cellSignalStrength = cell.cellSignalStrength
                Rlog.d(TAG, "NR cell: ${cellIdentity.operatorAlphaLong}, ${cellIdentity.operatorAlphaShort}, $cellIdentity")
            } else if (cell is CellInfoWcdma) {
                val cellIdentity = cell.cellIdentity
                val cellSignalStrength = cell.cellSignalStrength
                Rlog.d(
                    TAG,
                    "WCDMA cell: ${cellIdentity.cid}, ${cellIdentity.lac}, ${cellIdentity.mcc}, ${cellIdentity.mnc}, ${cellSignalStrength.dbm}",
                )
            } else if (cell is CellInfoGsm) {
                val cellIdentity = cell.cellIdentity
                val cellSignalStrength = cell.cellSignalStrength
                Rlog.d(
                    TAG,
                    "GSM cell: ${cellIdentity.cid}, ${cellIdentity.lac}, ${cellIdentity.mcc}, ${cellIdentity.mnc}, ${cellSignalStrength.dbm}",
                )
            }
        }

        // XXX samsung rom apparently regenerates local SPIC/SPIS every register,
        // this doesn't affect current connections but possibly affects new incoming
        // connections ? Just keep it constant for now
        // XXX samsung doesn't increment cnonce but it would be better to avoid replays?
        // well that'd only matter if the server refused replays, so keep as is.
        // XXX timeout/retry? notification on fail? receive on thread?

        val writer = _writer ?: socket.gWriter()

        fun secClient(
            alg: String,
            ealg: String,
        ) =
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=${ipsecSettings.clientSpiC.spi};spi-s=${ipsecSettings.clientSpiS.spi};port-c=${socket.gLocalPort()};port-s=${serverSocket.localPort};ealg=$ealg;alg=$alg"

        val algs = listOf("hmac-sha-1-96", "hmac-md5-96")
        val ealgs = listOf("null", "aes-cbc")
        val secClients = algs.flatMap { alg -> ealgs.map { ealg -> secClient(alg, ealg) } }
        val secClientLine =
            "Security-Client: ${secClients.joinToString(", ")}"

        // P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=216302ee2003a107
        val msg =
            SipRequest(
                SipMethod.REGISTER,
                "sip:$realm",
                // "sip:lte-lguplus.co.kr",
                registerHeaders +
                    """
                    Expires: 600000
                    Cseq: $registerCounter REGISTER
                    Contact: $contact
                    Supported: path, gruu, sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                    Authorization: $akaDigest
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    $secClientLine
                    """.toSipHeadersMap(),
            ) // route present on all calls except this
        Rlog.d(TAG, "Sending $msg")
        synchronized(writer) { writer.write(msg.toByteArray()) }
        registerCounter += 1
    }

    fun registerCallback(response: SipResponse): Boolean {
        // once we get there all register must be successful
        // on failure just abort thread, ims will restart
        require(response.statusCode == 200)

        val r = Regex("lr;[^>]*")
        val route =
            (
                response.headers.getOrDefault("service-route", emptyList()) +
                    response.headers.getOrDefault("path", emptyList())
            ).toSet() // remove duplicates
                .toList()
                .map {
                    r.replace(it, "lr")
                }

        val associatedUri =
            response.headers["p-associated-uri"]!!
                .flatMap { it.split(",") }
                .map { it.trimStart('<').trimEnd('>').split(':') }
        val preSip = associatedUri.first { it[0] == "sip" }[1]

        mySip = "sip:" + preSip
        myTel = associatedUri.firstOrNull { it[0] == "tel" }?.get(1) ?: preSip.split("@")[0]
        commonHeaders +=
            mapOf(
                "route" to route,
                "from" to listOf("<$mySip>"),
                "to" to listOf("<$mySip>"),
            )

        subscribe()
        // always keep callback
        return false
    }

    fun subscribe() {
        val local =
            if (socket.gLocalAddr() is Inet6Address) {
                "[${socket.gLocalAddr().hostAddress}]:${serverSocket.localPort}"
            } else {
                "${socket.gLocalAddr().hostAddress}:${serverSocket.localPort}"
            }
        val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
        val transport = if (socket is SipConnectionTcp) "tcp" else "udp"
        val contactTel =
            """<sip:$myTel@$local;transport=$transport>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
        val msg =
            SipRequest(
                SipMethod.SUBSCRIBE,
                "$mySip",
                commonHeaders +
                    """
                    Contact: $contactTel
                    P-Preferred-Identity: <$mySip>
                    Event: reg
                    Expires: 600000
                    Supported: sec-agree
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, INFO, MESSAGE, PRACK, OPTIONS
                    Accept: application/reginfo+xml
                    P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=20810b8c49752501
                    """.toSipHeadersMap(),
            )
        if (!imsReady) {
            setResponseCallback(msg.headers["call-id"]!![0], ::subscribeCallback)
        }
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
    }

    fun subscribeCallback(response: SipResponse): Boolean {
        /*if (response.statusCode != 200) {
            imsFailureCallback?.invoke()
            return true
        }*/
        imsReadyCallback?.invoke()
        imsReady = true
        return true
    }

    fun waitPrack(v: Int) {
        synchronized(prAckWaitLock) {
            while (prAckWait.contains(v)) {
                prAckWaitLock.wait(1000)
            }
        }
    }

    fun handlePrack(request: SipRequest): Int {
        Rlog.d(TAG, "Received PRACK for ${request.headers["rack"]!![0]}")
        synchronized(prAckWaitLock) {
            val id = request.headers["rack"]!![0].split(" ")[0].toInt()
            prAckWait -= id
            prAckWaitLock.notifyAll()
        }
        return 200
    }

    fun handleUpdate(request: SipRequest): Int {
        val call = currentCall!!
        val ipType = if (call.rtpRemoteAddr is Inet6Address) "IP6" else "IP4"
        val allTracks = listOf(call.pcmuTrack, call.dtmfTrack).sorted()
        val mySdp =
            """
v=0
o=- 1 2 IN $ipType ${socket.gLocalAddr().hostAddress}
s=phh voice call
c=IN $ipType ${socket.gLocalAddr().hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${call.rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=rtpmap:${call.pcmuTrack} PCMU/8000/1
a=rtpmap:${call.dtmfTrack} telephone-event/8000
a=ptime:20
a=maxptime:240
a=${call.dtmfTrackDesc}
a=curr:qos local sendrecv
a=curr:qos remote sendrecv
a=des:qos mandatory local sendrecv
a=des:qos mandatory remote sendrecv
a=sendrecv
                       """.trim().toByteArray()

        currentCall =
            Call(
                outgoing = call.outgoing,
                pcmuTrack = call.pcmuTrack,
                dtmfTrack = call.dtmfTrack,
                dtmfTrackDesc = call.dtmfTrackDesc,
                callHeaders = call.callHeaders,
                rtpRemoteAddr = call.rtpRemoteAddr,
                rtpRemotePort = call.rtpRemotePort,
                rtpSocket = call.rtpSocket,
                sdp = request.body,
                hasEarlyMedia = call.hasEarlyMedia,
                remoteContact = call.remoteContact,
            )

        val reply =
            SipResponse(
                statusCode = 200,
                statusString = "OK",
                headersParam =
                    request.headers.filter { (k, _) ->
                        k in listOf("cseq", "via", "from", "to", "call-id")
                    } +
                        """
                    Content-Type: application/sdp
                    Supported: 100rel, replaces, timer
                    Require: precondition
                    Call-ID: ${currentCall!!.callHeaders["call-id"]!![0]}
                """.toSipHeadersMap(),
                body = mySdp,
            )
        Rlog.d(TAG, "Replying back with $reply")
        synchronized(socket.gWriter()) { socket.gWriter().write(reply.toByteArray()) }

        if (call?.outgoing == false) {
            val myHeaders2 = call.callHeaders - "rseq" - "content-type" - "require"
            val msg2 =
                SipResponse(
                    statusCode = 180,
                    statusString = "Ringing",
                    headersParam = myHeaders2,
                )
            Rlog.d(TAG, "Sending $msg2")
            synchronized(socket.gWriter()) { socket.gWriter().write(msg2.toByteArray()) }
        }

        return 0
    }

    fun handleCancel(request: SipRequest): Int {
        // RFC 3261 §9.2: CANCEL has no effect if we already sent a final response (200 OK)
        if (callStarted.get()) {
            Rlog.d(TAG, "CANCEL received after 200 OK — ignoring per RFC 3261 §9.2")
            return 200
        }
        callStopped.set(true)
        Rlog.d(TAG, "Cancelled call ${request.headers["call-id"]!![0]}")

        // We're supposed to add an additional answer SIP/2.0 487 Request Terminated
        onCancelledCall?.invoke(Object(), "", emptyMap())
        return 200
    }

    data class Call(
        val outgoing: Boolean,
        val callHeaders: SipHeadersMap,
        val sdp: ByteArray,
        val pcmuTrack: Int,
        val dtmfTrack: Int,
        val dtmfTrackDesc: String,
        val rtpRemoteAddr: InetAddress,
        val rtpRemotePort: Int,
        val rtpSocket: DatagramSocket,
        val hasEarlyMedia: Boolean,
        val remoteContact: String,
    )

    @SuppressLint("MissingPermission")
    fun callEncodeThread() {
        val call = currentCall!!
        val gen = callGeneration.get()
        thread {
            var sequenceNumber = 0

            Rlog.d(TAG, "Encode thread started: pcmuTrack=${call.pcmuTrack} remote=${call.rtpRemoteAddr}:${call.rtpRemotePort} gen=$gen")
            val encoder = MediaCodec.createEncoderByType("audio/g711-mlaw")
            val mediaFormat = MediaFormat.createAudioFormat("audio/g711-mlaw", 8000, 1)
            // mediaFormat.setInteger(MediaFormat.KEY_BIT_RATE, 12200)
            // mediaFormat.setInteger(MediaFormat.KEY_PRIORITY, 0) //  0 = realtime priority, encoder will not fall behind
            encoder.configure(mediaFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            encoder.start()

            while (!callStarted.get()) {
                if (callStopped.get() || callGeneration.get() != gen) {
                    Rlog.d(TAG, "Silence loop exiting early: callStopped=${callStopped.get()}, genMismatch=${callGeneration.get() != gen}")
                    encoder.stop()
                    encoder.release()
                    return@thread
                }
                val timestamp = sequenceNumber * 160
                Thread.sleep(20)
                val rtpHeader =
                    listOf(
                        // RTP
                        0x80, // rtp version
                        call.pcmuTrack, // payload type
                        (sequenceNumber shr 8),
                        (sequenceNumber and 0xff),
                        (timestamp shr 24),
                        ((timestamp shr 16) and 0xff),
                        ((timestamp shr 8) and 0xff),
                        (timestamp and 0xff),
                        0x03,
                        0x00,
                        0xd2,
                        0x00, // SSRC
                    )
                val pcmuNothing = listOf(0x77, 0xc0) // CMR = 12.2kbps, F=0, FT=15=No TX/No RX, Q=1

                val buf = (rtpHeader + pcmuNothing).map { it.toUByte() }.toUByteArray().toByteArray()

                val dgramPacket =
                    DatagramPacket(buf, buf.size, call.rtpRemoteAddr, call.rtpRemotePort)
                call.rtpSocket.send(dgramPacket)
                sequenceNumber++
            }
            Rlog.d(TAG, "Silence loop exited after $sequenceNumber packets, starting real encoding")

            // DANGER: Don't open the mic before the user acknowledged opening the call!

            val minBufferSize = AudioRecord.getMinBufferSize(8000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
            val audioRecord =
                AudioRecord(
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                    8000,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    minBufferSize,
                )
            Rlog.d(TAG, "AudioRecord created with minBufferSize=$minBufferSize, state=${audioRecord.state}")

            // Pin capture to the built-in mic so the Samsung HAL cannot reroute it to
            // the baseband PCM path (pcmC0D110c) that produces silence for software IMS.
            // setPreferredDevice overrides HAL source-based routing while keeping
            // VOICE_COMMUNICATION semantics (call-mode output path stays correct).
            val audioManager = ctxt.getSystemService(android.media.AudioManager::class.java)
            val builtinMic =
                audioManager
                    .getDevices(android.media.AudioManager.GET_DEVICES_INPUTS)
                    .firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_MIC }
            if (builtinMic != null) {
                audioRecord.preferredDevice = builtinMic
                Rlog.d(TAG, "AudioRecord preferredDevice set to builtin mic: id=${builtinMic.id} name=${builtinMic.productName}")
            } else {
                Rlog.w(TAG, "AudioRecord: no TYPE_BUILTIN_MIC found, proceeding without preferredDevice")
            }

            val prevAudioMode = audioManager.mode
            audioManager.mode = android.media.AudioManager.MODE_IN_COMMUNICATION
            audioRecord.startRecording()
            Rlog.d(
                TAG,
                "AudioRecord started, state=${audioRecord.recordingState} audioMode=${audioManager.mode} (was $prevAudioMode) preferredDevice=${audioRecord.preferredDevice?.type}",
            )

            var firstPacket = true
            var realFrameCount = 0

            val buffer = ByteArray(minBufferSize)
            while (true) {
                if (callStopped.get() || callGeneration.get() != gen) break
                val nRead = audioRecord.read(buffer, 0, buffer.size)
                if (realFrameCount < 5) {
                    val allZero = buffer.take(nRead.coerceAtLeast(0)).all { it == 0.toByte() }
                    Rlog.d(TAG, "AudioRecord.read nRead=$nRead allZero=$allZero (bufferSize=${buffer.size})")
                }

                val inBufIdx = encoder.dequeueInputBuffer(-1)
                val inBuf = encoder.getInputBuffer(inBufIdx)!!
                inBuf.clear()
                inBuf.put(buffer, 0, nRead)

                // Fake timestamp but it is not appearing in the output stream anyway
                encoder.queueInputBuffer(inBufIdx, 0, nRead, System.nanoTime() / 1000, 0)

                // Drain all output frames the encoder produced for this input.
                // Use -1 (block) on the first call so we always wait for the async
                // C2 encoder to finish; use 0 on subsequent calls to collect any
                // additional frames without stalling.  Without draining, the output
                // queue fills up and dequeueInputBuffer(-1) deadlocks.
                val outBufInfo = MediaCodec.BufferInfo()
                var drainTimeout = -1L
                var outCount = 0
                while (true) {
                    val outBufIdx = encoder.dequeueOutputBuffer(outBufInfo, drainTimeout)
                    drainTimeout = 0L
                    if (outBufIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                        Rlog.d(TAG, "Encoder output format changed")
                        continue
                    }
                    if (outBufIdx < 0) {
                        if (outCount > 0) Rlog.d(TAG, "Drained $outCount output buffers")
                        break
                    }
                    outCount++

                    val outBuf = encoder.getOutputBuffer(outBufIdx)!!

                    val encoderData = ByteArray(outBufInfo.size)
                    outBuf.get(encoderData)
                    encoder.releaseOutputBuffer(outBufIdx, false)

                    if (realFrameCount == 0) {
                        Rlog.d(
                            TAG,
                            "First encoder output: size=${outBufInfo.size} raw=${encoderData.take(
                                32,
                            ).joinToString(" ") { "%02x".format(it) }}",
                        )
                    }

                    var bufPos = 0
                    while (bufPos < outBufInfo.size) {
                        val frameSize = 32
                        if (outBufInfo.size - bufPos < frameSize) break

                        // Encoder outputs octet-aligned PCMU frames (RFC 4867 §5):
                        //   byte 0 = frame header: [0][FT[3:0]][Q][PP]
                        //   bytes 1-31 = 244 payload bits, MSB-first, 4 bits zero-padding at end
                        val ft = (encoderData[bufPos].toUByte().toInt() shr 3) and 0xf
                        val q = (encoderData[bufPos].toUByte().toInt() shr 2) and 0x1

                        // Build RFC 4867 §4.4 bandwidth-efficient single-frame payload (32 bytes):
                        //   [CMR(4)][F(1)][FT(4)][Q(1)][payload_bits(244)][pad(2)]
                        // CMR=15 (0xF) = no codec-mode request; F=0 = last (only) frame.
                        val cmr = 0xf
                        val f = 0
                        // Byte 0: CMR[3:0] | F | FT[3:1]
                        val beByte0 = (cmr shl 4) or (f shl 3) or (ft shr 1)
                        // Byte 1: FT[0] | Q | payload[0:5]  (upper 6 bits of encoder byte 1)
                        val beByte1 =
                            ((ft and 1) shl 7) or (q shl 6) or
                                (encoderData[bufPos + 1].toUByte().toInt() shr 2)
                        // Bytes 2-31: slide a 2-bit window across encoder bytes 1-31
                        val beRest =
                            (1 until frameSize - 1).map { i ->
                                val lo = (encoderData[bufPos + i].toUByte().toInt() and 0x3) shl 6
                                val hi = (encoderData[bufPos + i + 1].toUByte().toInt() shr 2) and 0x3f
                                lo or hi
                            }

                        // Every 20 ms, at 8 kHz, we have 160 samples
                        val timestamp = sequenceNumber * 160
                        val rtpHeader =
                            byteArrayOf(
                                0x80.toByte(),
                                ((if (firstPacket) 0x80 else 0) or call.pcmuTrack).toByte(),
                                (sequenceNumber shr 8).toByte(),
                                (sequenceNumber and 0xff).toByte(),
                                (timestamp shr 24).toByte(),
                                ((timestamp shr 16) and 0xff).toByte(),
                                ((timestamp shr 8) and 0xff).toByte(),
                                (timestamp and 0xff).toByte(),
                                0x03,
                                0x00,
                                0xd2.toByte(),
                                0x00,
                            )
                        firstPacket = false

                        val buf =
                            rtpHeader +
                                byteArrayOf(beByte0.toByte(), beByte1.toByte()) +
                                beRest.map { it.toByte() }.toByteArray()

                        val dgramPacket = DatagramPacket(buf, buf.size, call.rtpRemoteAddr, call.rtpRemotePort)
                        try {
                            call.rtpSocket.send(dgramPacket)
                            if (realFrameCount < 10) {
                                Rlog.d(
                                    TAG,
                                    "Sent RTP packet #$sequenceNumber ft=$ft ts=$timestamp payload=${buf.drop(
                                        12,
                                    ).take(4).joinToString(" ") { "%02x".format(it) }}... to ${call.rtpRemoteAddr}:${call.rtpRemotePort}",
                                )
                            }
                            if (realFrameCount == 0) {
                                Rlog.d(TAG, "First RTP packet full hex: ${buf.joinToString(" ") { "%02x".format(it) }}")
                            }
                            if (sequenceNumber % 50 == 0 && realFrameCount >= 10) {
                                Rlog.d(
                                    TAG,
                                    "Sent RTP packet #$sequenceNumber ft=$ft ts=$timestamp to ${call.rtpRemoteAddr}:${call.rtpRemotePort}",
                                )
                            }
                        } catch (e: Exception) {
                            Rlog.e(TAG, "Failed to send RTP packet #$sequenceNumber: ${e.message}", e)
                        }

                        sequenceNumber++
                        realFrameCount++
                        bufPos += frameSize
                    }
                }
            }
            Rlog.d(
                TAG,
                "Encode thread exiting: callStopped=${callStopped.get()}, genMismatch=${callGeneration.get() != gen}, totalPacketsSent=$sequenceNumber",
            )
            audioRecord.stop()
            audioRecord.release()
            encoder.stop()
            encoder.release()
            audioManager.mode = prevAudioMode
        }
    }

    var currentCall: Call? = null

    fun acceptCall() {
        thread {
            // Wait for any outstanding PRACK acknowledgements before sending 200 OK (RFC 3262 §5)
            val pendingSeqs = synchronized(prAckWaitLock) { prAckWait.toSet() }
            pendingSeqs.forEach { waitPrack(it) }

            val local =
                if (socket.gLocalAddr() is Inet6Address) {
                    "[${socket.gLocalAddr().hostAddress}]:${serverSocket.localPort}"
                } else {
                    "${socket.gLocalAddr().hostAddress}:${serverSocket.localPort}"
                }
            val sipInstance = "<urn:gsma:imei:${imei.substring(0, 8)}-${imei.substring(8, 14)}-0>"
            val transport = if (socket is SipConnectionTcp) "tcp" else "udp"
            val evolvedContact =
                """<sip:$imsi@$local;transport=$transport>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+g.3gpp.mid-call;+g.3gpp.srvcc-alerting;+g.3gpp.ps2cs-srvcc-orig-pre-alerting"""

            Rlog.d(TAG, "Accepting call")
            val call = currentCall!!
            val myHeaders = call.callHeaders
            val myHeaders3 =
                myHeaders - "rseq" - "security-verify" +
                    """
                Session-Expires: 900;refresher=uas
                P-Preferred-Identity: <$mySip>
                Contact: $evolvedContact
                Content-Type: application/sdp
                """.toSipHeadersMap()

            // Normally we shouldn't send again the SDP. With "precondition" feature flag, the SDP in 183 Session Progress (then updated in UPDATE) should be used instead
            // But for some yet unknown reason, I need to do it (even though it contradicts my pcaps)
            val msg3 =
                SipResponse(
                    statusCode = 200,
                    statusString = "OK",
                    headersParam = myHeaders3,
                    body = call.sdp,
                )
            Rlog.d(TAG, "Sending $msg3")
            synchronized(socket.gWriter()) { socket.gWriter().write(msg3.toByteArray()) }

            callStarted.set(true)
        }
    }

    fun prack(resp: SipResponse) {
        val who = extractDestinationFromContact(resp.headers["contact"]!![0])
        val callId = resp.headers["call-id"]!![0]
        val rseq = resp.headers["rseq"]!![0]
        val whatToPrack = "$rseq ${resp.headers["cseq"]!![0]}"
        // PRACK is a request within the early dialog; route set comes from Record-Route
        // in the provisional response (RFC 3262 §4, RFC 3261 §12.1.2), not from the
        // registration Service-Route stored in commonHeaders.
        val dialogRoute = resp.headers["record-route"]
        val headers = if (dialogRoute != null) commonHeaders + ("route" to dialogRoute) else commonHeaders
        val msg =
            SipRequest(
                SipMethod.PRACK,
                who,
                headersParam =
                    headers +
                        """
                    RAck: $whatToPrack
                    Require: sec-agree
                    To: ${resp.headers["to"]!![0]}
                    From: ${resp.headers["from"]!![0]}
                    Call-Id: $callId
                    """.toSipHeadersMap(),
            )
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
    }

    fun rejectCall() {
        thread {
            val call = currentCall!!
            val headers = call.callHeaders
            val mySeqCounter = reliableSequenceCounter++
            val myHeaders = headers + "RSeq: $mySeqCounter".toSipHeadersMap()
            val msg =
                SipResponse(
                    statusCode = 486,
                    statusString = "Busy Here",
                    headersParam = myHeaders,
                )
            Rlog.d(TAG, "Sending $msg")
            synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }

            callStopped.set(true)
            onCancelledCall?.invoke(Object(), "", emptyMap())
        }
    }

    fun terminateCall() {
        callStopped.set(true)
        val call = currentCall ?: return
        // BYE is a dialog request; must use dialog route set (from 200 OK Record-Route)
        // stored in call.callHeaders, not the registration Service-Route in commonHeaders
        val byeHeaders = call.callHeaders.filterKeys { it != "content-type" }
        val bye =
            SipRequest(
                SipMethod.BYE,
                call.remoteContact,
                headersParam = byeHeaders,
            )
        Rlog.d(TAG, "Sending BYE $bye")
        synchronized(socket.gWriter()) { socket.gWriter().write(bye.toByteArray()) }
        onCancelledCall?.invoke(Object(), "", emptyMap())
    }

    /*
    Note: local/remote none/sendrecv are the precondition QoS status (RFC 3312).
    They signal that each side is pre-allocating media resources before the call is established.
    "none" = not yet ready, "sendrecv" = ready to send and receive.

    Outgoing call process — all messages are local→remote unless noted otherwise.
    This callback (setResponseCallback on the INVITE call-id) handles responses to our
    INVITE and to in-dialog requests we send (PRACK, UPDATE).  Incoming requests from the
    remote (e.g. the remote's UPDATE in step 8) are handled separately in parseMessage.

    1. Send INVITE with SDP:
         a=curr:qos local none   (we haven't allocated media yet)
         a=curr:qos remote none  (remote hasn't either)
         a=des:qos optional local/remote sendrecv
         Lists all tracks we support (PCMU, DTMF).

    2. Receive 100 Trying — ignored (no SDP → return false).

    3. Receive 183 Session Progress with remote SDP (track selected) and RSeq header.
       → Send PRACK for that RSeq, save 183 as respInFlight, return false (suspend processing).

    4. Receive 200 OK PRACK — resume processing the saved 183 (rseqHandled=true).
       Two sub-paths depending on whether the 183 carried Require: precondition:

       Path A — precondition present, local=none:
         → Start callDecodeThread + callEncodeThread (encoder sends silence, mic not open yet).
         → Send UPDATE claiming local=sendrecv (we have allocated our media resources).

       Path B — no precondition (or precondition already satisfied):
         → Start callDecodeThread + callEncodeThread immediately.
         → No UPDATE sent; proceed to wait for 180/200.

    5. [Path A] Receive 200 OK UPDATE — remote now reports sendrecv on both sides.
       Nothing to do in code; currentCall SDP was already updated when 200 arrived.

    6. [Path A] Receive another 183 Session Progress (no SDP, no new RSeq — no PRACK needed).
       → !isSdp → return false.

    7. [Handled in parseMessage, not here] Remote sends UPDATE with its final SDP.
       We respond 200 OK with our SDP.

    8. Receive 180 Ringing — no SDP → return false (just informs UI via onOutgoingCallConnected
       which is only fired on 200 OK, not here).

    9. Receive 200 OK on INVITE — call is accepted:
       → Send ACK (ACK to 2xx goes to Contact URI, routed via Record-Route; no response to ACK).
       → callStarted.set(true): encode thread exits silence loop, AudioRecord opens (mic live).
       → onOutgoingCallConnected invoked.

    Call is now running.

    Session timers (RFC 4028): we advertise Session-Expires: 900 / Supported: timer.
    The network nominates a refresher; if it nominates us (UAC), we must send a re-INVITE
    before the session expires. If it nominates itself (UAS), it sends re-INVITEs to us and
    we respond 200 OK (handled in parseMessage as an incoming INVITE).
    NOTE: periodic re-INVITE sending is not yet implemented for the UAC-refresher case.
     */

    var respInFlight: SipResponse? = null

    fun call(phoneNumber: String) {
        thread {
            callStopped.set(false)
            callStarted.set(false)
            threadsStarted.set(false)
            callGeneration.incrementAndGet()

            val rtpSocket = DatagramSocket(0, localAddr)
            network.bindSocket(rtpSocket)
            // rtpSocket.connect(rtpRemoteAddr, rtpRemotePort.toInt())
            Rlog.d(TAG, "RTP socket created for outgoing call: local=${rtpSocket.localAddress}:${rtpSocket.localPort}")

            val pcmuTrack = 0
            val dtmfTrack = 100
            val dtmfTrackDesc = "fmtp:100 0-15"
            val allTracks = listOf(pcmuTrack, dtmfTrack).sorted()

            val ipType = if (localAddr is Inet6Address) "IP6" else "IP4"

            val sdp =
                """
v=0
o=- 1 2 IN $ipType ${socket.gLocalAddr().hostAddress}
s=phh voice call
c=IN $ipType ${socket.gLocalAddr().hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=ptime:20
a=maxptime:240
a=rtpmap:$pcmuTrack PCMU/8000/1
a=rtpmap:$dtmfTrack telephone-event/8000
a=fmtp:$dtmfTrack 0-15
a=curr:qos local none
a=curr:qos remote none
a=des:qos optional local sendrecv
a=des:qos optional remote sendrecv
a=sendrecv
                       """.trim().toByteArray()

            val to = "tel:$phoneNumber;phone-context=ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
            val sipInstance = "<urn:gsma:imei:${imei.substring(0, 8)}-${imei.substring(8, 14)}-0>"
            val local =
                if (socket.gLocalAddr() is Inet6Address) {
                    "[${socket.gLocalAddr().hostAddress}]:${serverSocket.localPort}"
                } else {
                    "${socket.gLocalAddr().hostAddress}:${serverSocket.localPort}"
                }
            val transport = if (socket is SipConnectionTcp) "tcp" else "udp"
            val contactTel =
                """<sip:$myTel@$local;transport=$transport>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
            val myHeaders =
                commonHeaders +
                    """
                    From: <$mySip>
                    To: <$to>
                    P-Preferred-Identity: <$mySip>
                    P-Asserted-Identity: <$mySip>
                    Expires: 600000
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                    P-Early-Media: supported
                    Content-Type: application/sdp
                    Session-Expires: 900
                    Supported: 100rel, replaces, timer, precondition
                    Accept: application/sdp
                    Min-SE: 90
                    Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
                    P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
                    Contact: $contactTel
                    """.toSipHeadersMap() + generateCallId() - "p-asserted-identity"
            // P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
            // Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
            val msg =
                SipRequest(
                    SipMethod.INVITE,
                    to,
                    myHeaders,
                    sdp,
                )
            setResponseCallback(msg.headers["call-id"]!![0]) { r: SipResponse ->
                var resp = r
                var cseq = resp.headers["cseq"]!![0]

                var rseqHandled = false
                // If we stopped our process to PRACK a response, start again processing it
                if (cseq.contains("PRACK")) {
                    resp = respInFlight!!
                    respInFlight = null
                    cseq = resp.headers["cseq"]!![0]
                    rseqHandled = true
                }

                if (cseq.contains("ACK")) return@setResponseCallback false

                if (cseq.contains("INVITE") && (resp.statusCode == 200 || resp.statusCode == 202)) {
                    // ACK C-Seq must be the same as INVITE C-Seq
                    // Extract C-Seq
                    val cseqLine = resp.headers["cseq"]!![0]
                    val cseq = cseqLine.split(" ")[0].toInt()
                    val newTo = resp.headers["to"]!![0]
                    val newFrom = resp.headers["from"]!![0]
                    // ACK to 2xx must be sent to the Contact from the response (RFC 3261 §13.2.2.4)
                    val ackTo =
                        resp.headers["contact"]
                            ?.get(0)
                            ?.let { extractDestinationFromContact(it) } ?: to
                    // ACK is a dialog request; route set comes from Record-Route in the 200 OK
                    // (RFC 3261 §12.1.2), not from the registration Service-Route in myHeaders.
                    val dialogRoute = resp.headers["record-route"]
                    val ackHeaders = if (dialogRoute != null) myHeaders + ("route" to dialogRoute) else myHeaders
                    val msg2 =
                        SipRequest(
                            SipMethod.ACK,
                            ackTo,
                            ackHeaders - "content-type" +
                                """
                                CSeq: $cseq ACK
                                To: $newTo
                                From: $newFrom
                                """.toSipHeadersMap(),
                        )
                    Rlog.d(TAG, "Sending $msg2")
                    synchronized(socket.gWriter()) { socket.gWriter().write(msg2.toByteArray()) }
                    callStarted.set(true)
                    // Update dialog route set from the confirmed 200 OK (RFC 3261 §12.1.2)
                    // so that subsequent in-dialog requests (BYE, UPDATE) use the correct route.
                    val rrFrom200Ok = resp.headers["record-route"]
                    if (rrFrom200Ok != null) {
                        currentCall =
                            currentCall?.copy(
                                callHeaders = currentCall!!.callHeaders + ("route" to rrFrom200Ok),
                            )
                    }
                    Rlog.d(TAG, "Invite got SUCCESS")
                    onOutgoingCallConnected?.invoke(Object(), emptyMap())
                } else {
                    Rlog.d(TAG, "Invite got status ${resp.statusCode} = ${resp.statusString}")
                    if (resp.statusCode >= 400) {
                        onCancelledCall?.invoke(
                            Object(),
                            "",
                            mapOf(
                                "statusCode" to resp.statusCode.toString(),
                                "statusString" to resp.statusString,
                            ),
                        )
                        // The whole call failed, so drop that call-id
                        return@setResponseCallback true
                    }
                }

                if (resp.headers["rseq"]?.isNotEmpty() == true && !rseqHandled) {
                    prack(resp)
                    respInFlight = resp
                    return@setResponseCallback false
                }

                val isSdp = resp.headers["content-type"]?.get(0) == "application/sdp"
                val isPrecondition = resp.headers["require"]?.find { it.contains("precondition") } != null

                if (!isSdp) return@setResponseCallback false

                val respSdp =
                    resp.body
                        .toString(Charsets.UTF_8)
                        .split("[\r\n]+".toRegex())
                        .toList()

                fun sdpElement(command: String): String? {
                    val v = respSdp.firstOrNull { it.startsWith("$command=") } ?: return null
                    return v.substring(2)
                }
                val rtpRemotePort = sdpElement("m")!!.split(" ")[1]
                val rtpRemoteAddr = InetAddress.getByName(sdpElement("c")!!.split(" ")[2])
                currentCall =
                    Call(
                        outgoing = true,
                        pcmuTrack = pcmuTrack,
                        dtmfTrack = dtmfTrack,
                        dtmfTrackDesc = dtmfTrackDesc,
                        // Update from/to/call-id based on the response we got to include the remote tag
                        callHeaders =
                            myHeaders - "require" - "content-type" + ("from" to resp.headers["from"]!!) + ("to" to resp.headers["to"]!!) +
                                ("call-id" to resp.headers["call-id"]!!),
                        rtpRemoteAddr = rtpRemoteAddr,
                        rtpRemotePort = rtpRemotePort.toInt(),
                        rtpSocket = rtpSocket,
                        sdp = resp.body,
                        hasEarlyMedia = resp.headers["p-early-media"]?.isNotEmpty() == true,
                        remoteContact = extractDestinationFromContact(resp.headers["contact"]!![0]),
                    )

                // This isn't the answer to our INVITE, but to our later precondition UPDATE
                // TODO Actually check cseq
                if (resp.headers["cseq"]?.get(0)?.contains("UPDATE") == true) {
                    if (isSdp && resp.statusCode == 200) {
                        // Nothing to do here, we've already upgraded the call with the new SDP, everything's fine
                        return@setResponseCallback false
                    }
                }

                if (isPrecondition && resp.statusCode == 183) {
                    Rlog.d(TAG, "Handling precondition...")
                    val currLocal = respSdp.first { it.startsWith("a=curr:qos local") }
                    // No resource has been allocated at either side
                    val localNone = currLocal.contains("none")
                    Rlog.d(TAG, "precondition: Curr is $currLocal $localNone")
                    val currRemote = respSdp.first { it.startsWith("a=curr:qos remote") }
                    val remoteNone = currRemote.contains("none")

                    if (localNone) {
                        // "Allocating our local resource" and update the call
                        if (threadsStarted.compareAndSet(false, true)) {
                            callDecodeThread()
                            callEncodeThread()
                        }

                        val newSdp =
                            respSdp
                                .map { line ->
                                    if (line.startsWith("a=curr:qos local")) {
                                        "a=curr:qos local sendrecv"
                                    } else if (line.startsWith("a=des:qos mandatory local")) {
                                        "a=des:qos mandatory local sendrecv"
                                    } else {
                                        line
                                    }
                                }.joinToString("\r\n")
                                .toByteArray()

                        val msg2 =
                            SipRequest(
                                SipMethod.UPDATE,
                                to,
                                currentCall!!.callHeaders + ("content-type" to listOf("application/sdp")),
                                newSdp,
                            )
                        Rlog.d(TAG, "Sending $msg2")
                        synchronized(socket.gWriter()) { socket.gWriter().write(msg2.toByteArray()) }
                    }

                    return@setResponseCallback false
                }

                if (!isPrecondition && resp.statusCode == 183) {
                    if (threadsStarted.compareAndSet(false, true)) {
                        callDecodeThread()
                        callEncodeThread()
                    }
                }

                false // Return true when we want to stop receiving messages for that call
            }
            Rlog.d(TAG, "Sending $msg")
            synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
        }
    }

    fun callDecodeThread() {
        val gen = callGeneration.get()
        // Receiving thread
        thread {
            val minBufferSize = AudioTrack.getMinBufferSize(8000, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
            val audioTrack =
                AudioTrack(
                    AudioManager.STREAM_VOICE_CALL,
                    8000,
                    AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    minBufferSize,
                    AudioTrack.MODE_STREAM,
                )
            audioTrack.play()

            val decoder = MediaCodec.createDecoderByType("audio/g711-mlaw")
            val mediaFormat = MediaFormat.createAudioFormat("audio/g711-mlaw", 8000, 1)
            decoder.configure(mediaFormat, null, null, 0)
            decoder.start()

            var receivedCount = 0
            while (true) {
                if (callStopped.get() || callGeneration.get() != gen) break
                val dgramBuf = ByteArray(2048)
                val dgram = DatagramPacket(dgramBuf, dgramBuf.size)
                currentCall!!.rtpSocket.receive(dgram)
                receivedCount++

                // Check RTP payload type
                val pt = dgramBuf[1].toUByte().toInt() and 0x7f
                val ft = (dgramBuf[13].toUByte().toUInt() shr 7) or ((dgramBuf[12].toUByte().toUInt() and (7).toUInt()) shl 1)

                if (receivedCount % 50 == 0) {
                    Rlog.d(TAG, "Received RTP packet #$receivedCount: length=${dgram.length} pt=$pt ft=$ft")
                }

                if (ft.toInt() != 7) continue

                // RTP header 12 byte
                // PCMU in RTP header 10 bits
                // Packet size 32, FT=7
                val baOs = ByteArrayOutputStream()

                baOs.write(ft.toInt() shl 3)

                var m = 0
                // Warning: we should take good care counting the **bits** of the packet based on FT
                for (i in 13 until dgram.length) {
                    // Take 6 bits left, 2 bits right
                    val left = (dgramBuf[i].toUByte().toUInt().toInt() and 0x3f) shl 2
                    val right = (dgramBuf[i + 1].toUByte().toUInt().toInt() shr 6) and 0x3
                    m++
                    baOs.write(left or right)
                }
                // Rlog.d(TAG, "Received RTP data of length ${dgram.length} $m")

                val inBufIndex = decoder.dequeueInputBuffer(-1)
                // Rlog.d(TAG, "Got decoding input buffer $inBufIndex")
                val inBuf = decoder.getInputBuffer(inBufIndex)!!
                val data = baOs.toByteArray()
                inBuf.clear()
                inBuf.put(data)
                decoder.queueInputBuffer(inBufIndex, 0, data.size, 0, 0)

                // TODO: Support DTX (comfort noise frames that don't repeat)
                // TODO: Can we receive multiple outs per in?
                val outBufInfo = MediaCodec.BufferInfo()
                val outBufIndex = decoder.dequeueOutputBuffer(outBufInfo, 0)
                // Rlog.d(TAG, "Got decoding output buffer $outBufIndex")
                if (outBufIndex >= 0) {
                    val outBuf = decoder.getOutputBuffer(outBufIndex)!!
                    audioTrack.write(outBuf, outBufInfo.size, AudioTrack.WRITE_BLOCKING)
                    decoder.releaseOutputBuffer(outBufIndex, false)
                }
            }
            audioTrack.stop()
            audioTrack.release()
            decoder.stop()
            decoder.release()
        }
    }

    fun extractDestinationFromContact(contact: String): String {
        val r = Regex(".*<(sip:[^>]*)>.*")
        return r.find(contact)!!.groups[1]!!.value
    }

    val callStopped = AtomicBoolean(false)
    val callStarted = AtomicBoolean(false)
    val updateReceived = AtomicBoolean(false)
    val threadsStarted = AtomicBoolean(false)
    val callGeneration = AtomicInteger(0)

    val prAckWaitLock = Object()
    var prAckWait = mutableSetOf<Int>()

    fun handleCall(request: SipRequest): Int {
        val contentType = request.headers["content-type"]?.get(0)
        if (contentType != "application/sdp") return 404
        callStopped.set(false)
        callStarted.set(false)
        threadsStarted.set(false)
        callGeneration.incrementAndGet()

        val f = request.headers["from"]
        val r = Regex(".*(sip|tel):([^@]*).*")
        val m = r.find(f!![0]!!)!!.groups[2]!!.value
        Rlog.d(TAG, "Incoming call from $m")
        onIncomingCall?.invoke(Object(), m, mapOf("call-id" to request.headers["call-id"]!![0]))

        // We'll have three states:
        // - 100 Trying (this will be done by returning 100 in this function)
        // - 183 Session Progress network-wise we're ready to receive data
        // - 180 Ringing Notification's AudioTrack is playing, the user can hear its phone -- Note: Ringing doesn't give SDP
        // - 200 User has accepted the call

        val sdp =
            request.body
                .toString(Charsets.UTF_8)
                .split("[\r\n]+".toRegex())
                .toList()
        Rlog.d(TAG, "Split SDP into $sdp")

        fun sdpElement(command: String): String? {
            val v = sdp.firstOrNull { it.startsWith("$command=") } ?: return null
            return v.substring(2)
        }
        val sdpConnectionData = sdpElement("c")
        val sdpOrigin = sdpElement("o")
        val sdpSessionName = sdpElement("s")
        val sdpTiming = sdpElement("t")
        val sdpBandwidth = sdpElement("b")
        val sdpMedia = sdpElement("m")

        Rlog.d(TAG, "Got sdpTiming $sdpTiming")

        if (sdpTiming != "0 0") {
            Rlog.d(TAG, "Uh-oh, unknown timing mode")
        }

        val rtpRemote = sdpConnectionData!!.split(" ")[2] // c=IN IP6 xxx
        val rtpRemoteAddr = InetAddress.getByName(rtpRemote)
        val rtpRemotePort = sdpMedia!!.split(" ")[1] // m=audio 30798 RTP/AVP 96 97 98 8 18 101 100 99

        val attributes = sdp.filter { it.startsWith("a=") }.map { it.substring(2) }

        fun lookTrackMatching(
            codec: String,
            additional: String = "",
            notAdditional: String = "",
        ): Pair<Int, String>? {
            // TODO: also match on fmtp
            val maps = attributes.filter { it.startsWith("rtpmap") && it.contains(codec) }
            val matches =
                maps.map { m ->
                    val track = m.split("[: ]+".toRegex())[1].toInt()
                    val desc = m
                    Pair(track, desc)
                }
            Rlog.d(TAG, "Matching $codec, got $matches")
            val matches2 =
                if (matches.size > 1) {
                    matches.sortedBy { m ->
                        val fmtp = attributes.filter { it.startsWith("fmtp:${m.first}") }[0]
                        Rlog.d(TAG, "Matching $codec, for match $m got fmtp $fmtp")
                        if (fmtp.contains(additional)) {
                            0
                        } else if (notAdditional.isNotEmpty() && !fmtp.contains(notAdditional)) {
                            1
                        } else {
                            2
                        }
                    }
                } else {
                    matches
                }
            Rlog.d(TAG, "Matching2 $codec, got $matches2")
            return matches2.firstOrNull()
        }

        fun trackRequirements(track: Int): String? = attributes.firstOrNull { it.startsWith("fmtp:$track") }

        val hasEarlyMedia = request.headers["p-early-media"]?.isNotEmpty() == true
        val callerSupportsPrecondition =
            (
                request.headers["supported"].orEmpty() +
                    request.headers["require"].orEmpty()
            ).any { it.contains("precondition") }

        // Look for an PCMU/8000 mode
        val (pcmuTrack) = lookTrackMatching("PCMU/8000")!!

        // Look for a DTMF track, use the 8000Hz-based one to match PCMU timestamps
        val (dtmfTrack, dtmfTrackDesc) = lookTrackMatching("telephone-event/8000")!!

        val allTracks = listOf(pcmuTrack, dtmfTrack).sorted()
        // destination is sip:<owner>@realm, extract owner
        val owner = request.destination.substringAfter("sip:").substringBefore("@")

        thread {
            // Need to sleep a bit so that our 100 Trying is sent first. Kinda weird.
            Thread.sleep(500)
            val rtpSocket = DatagramSocket(0, localAddr)
            network.bindSocket(rtpSocket)
            rtpSocket.connect(rtpRemoteAddr, rtpRemotePort.toInt())
            Rlog.d(
                TAG,
                "RTP socket created: local=${rtpSocket.localAddress}:${rtpSocket.localPort}, remote=${rtpSocket.inetAddress}:${rtpSocket.port}",
            )

            val local =
                if (socket.gLocalAddr() is Inet6Address) {
                    "[${socket.gLocalAddr().hostAddress}]:${serverSocket.localPort}"
                } else {
                    "${socket.gLocalAddr().hostAddress}:${serverSocket.localPort}"
                }
            val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
            val contactTel =
                """<sip:$myTel@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
            val mySeqCounter = reliableSequenceCounter++
            val ipType = if (socket.gLocalAddr() is Inet6Address) "IP6" else "IP4"
            val mySdp =
                (
                    """
v=0
o=$owner 1 2 IN $ipType ${socket.gLocalAddr().hostAddress}
s=phh voice call
c=IN $ipType ${socket.gLocalAddr().hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=ptime:20
a=maxptime:240
a=$dtmfTrackDesc
a=fmtp:$pcmuTrack mode-set=7;octet-align=0;max-red=0
a=fmtp:$dtmfTrack 0-15
${if (callerSupportsPrecondition) {
                        """
a=curr:qos local none
a=curr:qos remote none
a=des:qos mandatory local sendrecv
a=des:qos mandatory remote sendrecv
a=conf:qos remote sendrecv
                        """.trimIndent()
                    } else {
                        ""
                    }}
a=sendrecv
                       """.trim()
                ).toByteArray()

            // Generate a single local tag for all responses in this dialog (RFC 3261 §12.1.1)
            val localToTag = randomBytes(6).toHex()
            val toWithTag =
                request.headers["to"]!!.map { h ->
                    if (h.contains(";tag=")) h else "$h;tag=$localToTag"
                }

            val myHeaders =
                commonHeaders + // Require: precondition
                    """
                        Contact: $contactTel
                        Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, INFO, MESSAGE, PRACK, OPTIONS
                        Content-Type: application/sdp
                        Require: 100rel${if (callerSupportsPrecondition) ", precondition" else ""}
                        RSeq: $mySeqCounter
                        P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=20810b8c49752501
                        """.toSipHeadersMap() +
                    request.headers.filter { (k, _) -> k in listOf("cseq", "via", "from", "to", "call-id") } +
                    mapOf("to" to toWithTag) -
                    "route" - "security-verify"

            currentCall =
                Call(
                    outgoing = false,
                    pcmuTrack = pcmuTrack,
                    dtmfTrack = dtmfTrack,
                    dtmfTrackDesc = dtmfTrackDesc,
                    callHeaders = myHeaders - "require" - "content-type" + "Supported: 100rel, replaces, timer".toSipHeadersMap(),
                    rtpRemoteAddr = rtpRemoteAddr,
                    rtpRemotePort = rtpRemotePort.toInt(),
                    rtpSocket = rtpSocket,
                    sdp = mySdp,
                    hasEarlyMedia = hasEarlyMedia,
                    remoteContact = extractDestinationFromContact(request.headers["contact"]!![0]),
                )

            if (threadsStarted.compareAndSet(false, true)) {
                callDecodeThread()
                callEncodeThread()
            }

            synchronized(prAckWaitLock) {
                prAckWait += mySeqCounter
            }
            if (hasEarlyMedia) {
                val msg =
                    SipResponse(
                        statusCode = 183,
                        statusString = "Session Progress",
                        headersParam = myHeaders,
                        body = mySdp,
                    )
                Rlog.d(TAG, "Sending $msg")
                synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
                waitPrack(mySeqCounter)
            }
            if (!hasEarlyMedia) {
                val myHeaders2 =
                    myHeaders - "rseq" - "content-type" - "require" +
                        """
Supported: 100rel, replaces, timer
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500620f331a5e06

""".toSipHeadersMap()
                val msg2 =
                    SipResponse(
                        statusCode = 180,
                        statusString = "Ringing",
                        headersParam = myHeaders2,
                    )
                Rlog.d(TAG, "Sending $msg2")
                synchronized(socket.gWriter()) { socket.gWriter().write(msg2.toByteArray()) }
            }
        }

        // Next step is 180 Ringing, handled in the thread
        if (!hasEarlyMedia) {
            return 0
        }
        return 100
    }

    fun handleSms(request: SipRequest): Int {
        val sms = request.body.SipSmsDecode()
        if (sms == null) {
            Rlog.w(TAG, "Could not decode sms pdu")
            return 500
        }
        Rlog.d(TAG, "Decoded SMS type ${sms.type}, ${sms.pdu?.toString()}")
        when (sms.type) {
            SmsType.RP_DATA_FROM_NETWORK -> {
                val receivedCb = onSmsReceived
                if (receivedCb == null) {
                    Rlog.d(TAG, "No onSmsReceived callback!")
                    return 500
                }

                val token = smsLock.withLock { smsToken++ }
                val dest =
                    request.headers["from"]!![0]
                        .getParams()
                        .component1()
                        .trimStart('<')
                        .trimEnd('>')
                val callId = request.headers["call-id"]!![0]
                val cseq = request.headers["cseq"]!![0]
                smsHeadersMap[token] = smsHeaders(dest, callId, cseq)
                try {
                    receivedCb(token, "3gpp", sms.pdu!!)
                } catch (t: Throwable) {
                    Rlog.d(TAG, "Failed sending SMS to framework", t)
                }
            }

            SmsType.RP_ACK_FROM_NETWORK -> {
                try {
                    onSmsStatusReportReceived?.invoke(sms.ref.toInt(), "3gpp", ByteArray(2))
                } catch (t: Throwable) {
                    Rlog.d(TAG, "Failed sending SMS ACK to framework", t)
                }
            }

            SmsType.RP_ERROR_FROM_NETWORK -> {
                Rlog.d(TAG, "SMS error from network")
            }

            else -> {
                return 500
            }
        }
        return 200
    }

    fun sendSms(
        smsSmsc: String?,
        pdu: ByteArray,
        ref: Int,
        successCb: (() -> Unit),
        failCb: (() -> Unit),
    ) {
        val decodableSmsc =
            try {
                PhoneNumberUtils.numberToCalledPartyBCD(smsSmsc, PhoneNumberUtils.BCD_EXTENDED_TYPE_CALLED_PARTY)
                true
            } catch (t: Throwable) {
                false
            }

        val smsManager =
            ctxt.getSystemService(SmsManager::class.java).createForSubscriptionId(subId)
        val smscIdentity =
            try {
                val i =
                    smsManager
                        .javaClass
                        .getMethod("getSmscIdentity")
                        .invoke(smsManager) as Uri
                if (i.host == null) null else i
            } catch (t: Throwable) {
                null
            }
        Rlog.d(TAG, "Got smscIdentity $smscIdentity")
        // make ref up?
        val smsc =
            if (smsSmsc != null && decodableSmsc) {
                smsSmsc
            } else if (forceSmsc != null) {
                forceSmsc
            } else {
                try {
                    Rlog.d(
                        TAG,
                        "Got smsc $smscIdentity // host is ${smscIdentity?.host} // ${smscIdentity?.scheme} // ${smscIdentity?.path}",
                    )
                    smscIdentity!!.host!!
                } catch (t: Throwable) {
                    try {
                        Rlog.d(TAG, "getSmscIdentity failed", t)
                        val smscStr = smsManager.smscAddress
                        val smscMatchRegex = Regex("([0-9]+)")
                        Rlog.d(TAG, "Got smsc $smscStr, match ${smscMatchRegex.find(smscStr!!)}")
                        val match = smscMatchRegex.find(smscStr!!)!!
                        match.groupValues[1]
                    } catch (t: Throwable) {
                        Rlog.d(TAG, "smscAddress failed", t)
                        null
                    }
                }
            }

        // smsc
        val data = SipSmsEncodeSms(ref.toByte(), if (smsc == null) "" else "+$smsc", pdu)
        Rlog.d(TAG, "sending sms ${data.toHex()} to smsc $smsc")
        val dest =
            if (smscIdentity != null) {
                "sip:$smscIdentity"
            } else {
                "sip:+$smsc@$realm"
            }

        // "sip:ipsmgw.lte-lguplus.co.kr",
        val msg =
            SipRequest(
                SipMethod.MESSAGE,
                "sip:${smscIdentity ?: realm}",
                commonHeaders +
                    """
                    From: <$mySip>
                    To: <$dest>
                    P-Preferred-Identity: <$mySip>
                    P-Asserted-Identity: <$mySip>
                    Expires: 600000
                    Content-Type: application/vnd.3gpp.sms
                    Supported: sec-agree, path
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: MESSAGE
                    Accept-Contact: *;+g.3gpp.smsip;require;explicit
                    Request-Disposition: no-fork
                    """.toSipHeadersMap(),
                data,
            )
        setResponseCallback(
            msg.headers["call-id"]!![0],
            { resp: SipResponse ->
                if (resp.statusCode == 200 || resp.statusCode == 202) {
                    successCb()
                } else {
                    failCb()
                }
                true
            },
        )
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
    }

    fun sendSmsAck(
        token: Int,
        ref: Int,
        error: Boolean,
    ) {
        Rlog.d(TAG, "sending sms ack")
        val body = SipSmsEncodeAck(ref.toByte())
        val headers = smsHeadersMap.remove(token)
        if (headers == null) {
            // XXX return error?
            return
        }
        // do not send ack on error
        // Should we send an error report?
        if (error) {
            return
        }
        val msg =
            SipRequest(
                SipMethod.MESSAGE,
                headers.dest,
                commonHeaders +
                    """
                    Cseq: ${headers.cseq}
                    In-Reply-To: ${headers.callId}
                    Content-Type: application/vnd.3gpp.sms
                    Proxy-Require: sec-agree
                    Require: sec-agree
                    Allow: MESSAGE
                    Supported: path, gruu, sec-agree
                    Request-Disposition: no-fork
                    Accept-Contact: *;+g.3gpp.smsip
                    """.toSipHeadersMap(),
                body,
            )
        // ignore response
        setResponseCallback(msg.headers["call-id"]!![0], { true })
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.gWriter()) { socket.gWriter().write(msg.toByteArray()) }
    }
}
