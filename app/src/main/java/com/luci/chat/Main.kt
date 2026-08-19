package com.luci.chat

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connections.*
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

data class Peer(val id: String, val name: String, val pub: String, val connected: Boolean = false)
data class Msg(val from: String, val text: String, val time: Long, val mine: Boolean, val kind: String)

object Crypto {
    fun newKeyPair(): KeyPair {
        val g = KeyPairGenerator.getInstance("EC"); g.initialize(ECGenParameterSpec("secp256r1"))
        return g.generateKeyPair()
    }
    fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
    fun pubFromB64(s: String) = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(unb64(s)))
    fun privFromB64(s: String) = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(unb64(s)))
    fun aesKey(priv: java.security.PrivateKey, pub: java.security.PublicKey): SecretKeySpec {
        val ka = KeyAgreement.getInstance("ECDH"); ka.init(priv); ka.doPhase(pub, true)
        return SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(ka.generateSecret()), "AES")
    }
    fun encrypt(k: SecretKeySpec, plain: ByteArray): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, k, GCMParameterSpec(128, iv))
        return iv + c.doFinal(plain)
    }
    fun decrypt(k: SecretKeySpec, d: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, d.copyOfRange(0, 12)))
        return c.doFinal(d.copyOfRange(12, d.size))
    }
    fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}

object Store {
    lateinit var prefs: SharedPreferences
    var myId = ""
    var keyPair: KeyPair? = null
    val username = mutableStateOf("")
    val peers = mutableStateMapOf<String, Peer>()
    val messages = mutableStateOf<Map<String, List<Msg>>>(emptyMap())
    val screen = mutableStateOf<String?>(null)
    val keys = ConcurrentHashMap<String, SecretKeySpec>()

    fun boot(ctx: Context) {
        prefs = ctx.getSharedPreferences("luci", 0)
        val name = prefs.getString("name", null) ?: return
        val priv = prefs.getString("priv", null) ?: return
        val pub = prefs.getString("pub", "")
        keyPair = KeyPair(Crypto.pubFromB64(pub), Crypto.privFromB64(priv))
        myId = Crypto.sha(pub).take(10)
        username.value = name
        try {
            val arr = JSONArray(prefs.getString("contacts", "[]"))
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                peers[o.getString("id")] = Peer(o.getString("id"), o.getString("name"), o.getString("pub"))
                keys[o.getString("id")] = Crypto.aesKey(keyPair!!.private, Crypto.pubFromB64(o.getString("pub")))
            }
        } catch (_: Exception) {}
        val map = mutableMapOf<String, List<Msg>>()
        for (pid in peers.keys) {
            val list = mutableListOf<Msg>()
            try {
                val a = JSONArray(prefs.getString("msgs_$pid", "[]"))
                for (i in 0 until a.length()) {
                    val o = a.getJSONObject(i)
                    list.add(Msg(o.getString("f"), o.getString("t"), o.getLong("time"), o.getBoolean("mine"), o.getString("kind")))
                }
            } catch (_: Exception) {}
            map[pid] = list
        }
        messages.value = map
    }

    fun initIdentity(ctx: Context, name: String) {
        prefs = ctx.getSharedPreferences("luci", 0)
        val kp = Crypto.newKeyPair(); keyPair = kp
        val pub = Crypto.pubToB64(kp.public)
        myId = Crypto.sha(pub).take(10)
        username.value = name
        prefs.edit().putString("name", name).putString("pub", pub)
            .putString("priv", Crypto.b64(kp.private.encoded)).apply()
    }

    fun addPeer(p: Peer) {
        peers[p.id] = p
        keys[p.id] = Crypto.aesKey(keyPair!!.private, Crypto.pubFromB64(p.pub))
        val arr = JSONArray()
        for (q in peers.values) arr.put(JSONObject().put("id", q.id).put("name", q.name).put("pub", q.pub))
        prefs.edit().putString("contacts", arr.toString()).apply()
        if (!messages.value.containsKey(p.id)) messages.value = messages.value + (p.id to emptyList())
    }

    fun setConnected(pid: String, c: Boolean) { peers[pid]?.let { peers[pid] = it.copy(connected = c) } }

    fun addMsg(pid: String, m: Msg) {
        messages.value = messages.value + (pid to ((messages.value[pid] ?: emptyList()) + m))
        val a = JSONArray()
        for (x in messages.value[pid]!!) a.put(JSONObject().put("f", x.from).put("t", x.text).put("time", x.time).put("mine", x.mine).put("kind", x.kind))
        prefs.edit().putString("msgs_$pid", a.toString()).apply()
    }
}

class NearCtl(val ctx: Context) : PayloadCallback() {
    val client = Nearby.getConnectionsClient(ctx)
    val main = Handler(Looper.getMainLooper())
    val endpoints = ConcurrentHashMap<String, String>()
    val outbox = ConcurrentLinkedQueue<ByteArray>()
    val seen = ConcurrentHashMap.newKeySet<String>()
    val pendingMeta = ConcurrentHashMap<String, JSONObject>()
    private val SERVICE = "com.luci.chat.v3"

    val lifecycleCb = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(id: String, info: ConnectionInfo) { client.acceptConnection(id, this@NearCtl) }
        override fun onConnectionResult(id: String, res: ConnectionResolution) {
            if (res.status.isSuccess || res.status.statusCode == ConnectionsStatusCodes.STATUS_ALREADY_CONNECTED_TO_ENDPOINT) sendHello(id)
        }
        override fun onDisconnected(id: String) {
            val pid = endpoints.remove(id) ?: return
            main.post { Store.setConnected(pid, false) }
        }
    }
    val discoveryCb = object : DiscoveryEndpointCallback() {
        override fun onEndpointFound(id: String, a: String, b: String, c: String) {
            client.requestConnection(Store.username.value, id, lifecycleCb)
        }
        override fun onEndpointLost(id: String) {}
    }

    fun toast(s: String) = main.post { Toast.makeText(ctx, s, Toast.LENGTH_LONG).show() }

    fun start() {
        try {
            client.startAdvertising(Store.username.value, SERVICE, lifecycleCb,
                AdvertisingOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
            client.startDiscovery(SERVICE, discoveryCb,
                DiscoveryOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
        } catch (e: Exception) { toast("بلوتوث و وای‌فای را روشن کنید") }
    }

    fun sendHello(ep: String) {
        val j = JSONObject().put("kind", "hello").put("from", Store.myId)
            .put("name", Store.username.value).put("pub", Crypto.pubToB64(Store.keyPair!!.public))
        client.sendPayload(ep, Payload.fromBytes(j.toString().toByteArray()))
    }

    override fun onPayloadReceived(ep: String, p: Payload) {
        when (p.type) {
            Payload.Type.BYTES -> onBytes(ep, p.asBytes()!!)
            Payload.Type.FILE -> onFile(ep, p.asFile()!!)
            else -> {}
        }
    }
    override fun onPayloadTransferUpdate(ep: String, u: PayloadTransferUpdate) {}

    fun onBytes(ep: String, bytes: ByteArray) {
        try {
            val j = JSONObject(String(bytes))
            if (j.getString("kind") == "hello") {
                main.post {
                    val pid = j.getString("from")
                    if (pid != Store.myId) {
                        endpoints[ep] = pid
                        Store.addPeer(Peer(pid, j.getString("name"), j.getString("pub"), true))
                        for (b in outbox) client.sendPayload(ep, Payload.fromBytes(b))
                    }
                }
            } else {
                val id = j.optString("id", "")
                if (id.isNotEmpty() && !seen.add(id)) return
                if (j.getString("to") == Store.myId) main.post { deliver(j) }
                relay(ep, j)
            }
        } catch (_: Exception) {}
    }

    fun deliver(j: JSONObject) {
        val from = j.getString("from")
        val key = Store.keys[from] ?: return
        try {
            if (j.getString("kind") == "text") {
                val txt = String(Crypto.decrypt(key, Crypto.unb64(j.getString("data"))))
                Store.addMsg(from, Msg(from, txt, System.currentTimeMillis(), false, "text"))
            } else {
                pendingMeta[from] = JSONObject(String(Crypto.decrypt(key, Crypto.unb64(j.getString("data")))))
            }
        } catch (_: Exception) {}
    }

    // رلهٔ چندپرشی: پیامِ نه‌مقصودِ من را به بقیه می‌رساند
    fun relay(fromEp: String, j: JSONObject) {
        val ttl = j.optInt("ttl", 3)
        if (ttl <= 0) return
        j.put("ttl", ttl - 1)
        val nb = j.toString().toByteArray()
        if (outbox.size < 300) outbox.add(nb)
        main.post { for ((ep, _) in endpoints) if (ep != fromEp) client.sendPayload(ep, Payload.fromBytes(nb)) }
    }

    fun broadcast(bytes: ByteArray) {
        if (outbox.size < 300) outbox.add(bytes)
        for ((ep, _) in endpoints) client.sendPayload(ep, Payload.fromBytes(bytes))
    }

    fun sendText(pid: String, text: String) {
        val key = Store.keys[pid] ?: return
        val j = JSONObject().put("kind", "text").put("from", Store.myId).put("to", pid)
            .put("ttl", 3).put("id", Crypto.sha(System.currentTimeMillis().toString() + text).take(12))
            .put("data", Crypto.b64(Crypto.encrypt(key, text.toByteArray())))
        broadcast(j.toString().toByteArray())
        Store.addMsg(pid, Msg(Store.myId, text, System.currentTimeMillis(), true, "text"))
    }

    fun sendFile(pid: String, uri: Uri) {
        val key = Store.keys[pid] ?: return toast("ابتدا اتصال برقرار شود")
        try {
            val mime = ctx.contentResolver.getType(uri) ?: "file/bin"
            val name = (if (mime.startsWith("image")) "img_" else "vid_") + System.currentTimeMillis() +
                (if (mime.contains("mp4")) ".mp4" else if (mime.contains("jpeg")) ".jpg" else ".dat")
            val src = ctx.contentResolver.openInputStream(uri) ?: return
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val enc = File(ctx.cacheDir, "send.luci")
            enc.outputStream().use { o -> o.write(iv); CipherOutputStream(o, c).use { src.copyTo(it) } }
            val meta = JSONObject().put("kind", "filemeta").put("from", Store.myId).put("to", pid).put("ttl", 0)
                .put("id", Crypto.sha(name).take(12))
                .put("data", Crypto.b64(Crypto.encrypt(key, JSONObject().put("name", name).toString().toByteArray())))
            broadcast(meta.toString().toByteArray())
            for ((ep, p) in endpoints) if (p == pid) client.sendPayload(ep, Payload.fromFile(enc))
            Store.addMsg(pid, Msg(Store.myId, name, System.currentTimeMillis(), true, "file"))
            toast("در حال ارسال فایل…")
        } catch (e: Exception) { toast("خطا در ارسال فایل") }
    }

    fun onFile(ep: String, f: File) {
        val pid = endpoints[ep] ?: return
        val meta = pendingMeta.remove(pid) ?: return
        val key = Store.keys[pid] ?: return
        try {
            val out = File(File(ctx.getExternalFilesDir(null), "LUCI_Media").apply { mkdirs() }, meta.getString("name"))
            f.inputStream().use { ins ->
                val iv = ByteArray(12); ins.read(iv)
                val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                CipherInputStream(ins, c).use { cin -> out.outputStream().use { o -> cin.copyTo(o) } }
            }
            f.delete()
            main.post { Store.addMsg(pid, Msg(pid, out.absolutePath, System.currentTimeMillis(), false, "file")); toast("فایل دریافت شد ✔") }
        } catch (_: Exception) {}
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Store.boot(this)
        setContent { LuciApp() }
    }
}

val Purple = Color(0xFF8B5CF6)
val Cyan = Color(0xFF22D3EE)

fun Modifier.glass(shape: RoundedCornerShape = RoundedCornerShape(24)) = this
    .background(Brush.linearGradient(listOf(Color.White.copy(0.20f), Color.White.copy(0.06f))), shape)
    .border(1.dp, Color.White.copy(0.30f), shape)

@Composable
fun LuciApp() {
    val ctx = LocalContext.current
    val near = remember { mutableStateOf<NearCtl?>(null) }
    val perm = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }
    val perms = arrayOf(
        android.Manifest.permission.BLUETOOTH_ADVERTISE, android.Manifest.permission.BLUETOOTH_CONNECT,
        android.Manifest.permission.BLUETOOTH_SCAN, android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.ACCESS_COARSE_LOCATION, android.Manifest.permission.POST_NOTIFICATIONS)
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        Box(Modifier.fillMaxSize().background(Brush.linearGradient(listOf(Color(0xFF070B1E), Color(0xFF2B1E5E), Color(0xFF0C3B4C))))) {
            if (Store.username.value.isEmpty()) {
                Onboarding { name ->
                    Store.initIdentity(ctx, name)
                    near.value = NearCtl(ctx).also { it.start() }
                    perm.launch(perms)
                }
            } else {
                LaunchedEffect(Unit) {
                    if (near.value == null) near.value = NearCtl(ctx).also { it.start() }
                    perm.launch(perms)
                }
                MainScreen(near)
            }
        }
    }
}

@Composable
fun Onboarding(onStart: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Text("LUCI chat", fontSize = 40.sp, fontWeight = FontWeight.Black, color = Color.White)
        Text("چت آفلاین • رمزنگاری سرتاسری • بدون اینترنت", color = Color.White.copy(0.7f), fontSize = 14.sp)
        Spacer(Modifier.height(36.dp))
        Column(Modifier.glass().padding(24.dp).fillMaxWidth()) {
            Text("نام کاربری دائمی خودت را بنویس", color = Color.White.copy(0.85f), fontSize = 14.sp)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(value = name, onValueChange = { name = it }, modifier = Modifier.fillMaxWidth(),
                singleLine = true, placeholder = { Text("مثلاً Abolfazl", color = Color.White.copy(0.4f)) },
                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Cyan, unfocusedBorderColor = Color.White.copy(0.3f),
                    focusedTextColor = Color.White, unfocusedTextColor = Color.White, cursorColor = Cyan))
            Spacer(Modifier.height(20.dp))
            Button(onClick = { if (name.isNotBlank()) onStart(name.trim()) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent)) {
                Box(Modifier.fillMaxSize().background(Brush.horizontalGradient(listOf(Purple, Cyan)), RoundedCornerShape(16.dp)),
                    contentAlignment = Alignment.Center) {
                    Text("ورود به LUCI", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                }
            }
        }
    }
}

@Composable
fun MainScreen(near: MutableState<NearCtl?>) {
    val sel by Store.screen
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().glass(RoundedCornerShape(0)).padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            if (sel != null) Text("بازگشت", color = Cyan, fontSize = 14.sp, modifier = Modifier.clickable { Store.screen.value = null })
            else Text("LUCI", color = Color.White, fontWeight = FontWeight.Black, fontSize = 22.sp)
            val on = Store.peers.values.count { it.connected }
            Text("اطرافیان: ${Store.peers.size} • متصل: $on", color = Cyan, fontSize = 12.sp)
        }
        if (sel == null) PeerList() else ChatScreen(sel!!, near)
    }
}

@Composable
fun PeerList() {
    if (Store.peers.isEmpty()) {
        Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Text("📡", fontSize = 50.sp)
            Text("بلوتوث و وای‌فای را روشن کنید", color = Color.White.copy(0.8f))
            Text("دستگاه‌های اطراف خودکار پیدا می‌شوند", color = Color.White.copy(0.5f), fontSize = 12.sp)
        }
    } else {
        LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            items(Store.peers.values.toList()) { p ->
                Row(Modifier.fillMaxWidth().glass().clickable { Store.screen.value = p.id }.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(48.dp).clip(CircleShape).background(Brush.linearGradient(listOf(Purple, Cyan))),
                        contentAlignment = Alignment.Center) {
                        Text(p.name.take(1), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 20.sp)
                    }
    
