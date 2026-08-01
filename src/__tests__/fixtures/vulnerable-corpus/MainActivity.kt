/**
 * Intentionally vulnerable Android/Kotlin activity — corpus fixture for
 * the KT-* rule family.
 */
package com.example.vulnerable

import android.content.ClipData
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

// KT-CRED001: hardcoded API key
const val API_KEY = "sk-live-1234567890abcdef"

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)
        // KT-AUTH001: JS enabled in WebView
        webView.settings.setJavaScriptEnabled(true)
        // KT-AUTH002: JS bridge exposed to loaded pages
        webView.addJavascriptInterface(NativeBridge(), "Native")
        // KT-XSS001 / KT-XSS002: file and content access from WebView
        webView.settings.setAllowFileAccess(true)
        webView.settings.setAllowContentAccess(true)
        // KT-XSS003: mixed content allowed
        webView.settings.setMixedContentMode(0)

        // KT-AUTH003: broadcast without a permission
        sendBroadcast(Intent("com.example.SYNC_DONE"))

        // KT-ENC001: java.util.Random for a token
        val token = java.util.Random().nextInt().toString()

        // KT-ENC002: secrets in SharedPreferences
        val prefs = getSharedPreferences("auth", MODE_PRIVATE)
        prefs.edit().putString("token", token).apply()

        // KT-ENC003: hardcoded key material
        val keySpec = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        // KT-ENC004: weak cipher / digest
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val digest = MessageDigest.getInstance("MD5")

        // KT-FILE002: writing to shared external storage
        val export = android.os.Environment.getExternalStorageDirectory()

        // KT-LOG001: logging sensitive values
        Log.d("Auth", "token=$token key=$API_KEY")

        // KT-LOG002: secret on the clipboard
        val clip = ClipData.newPlainText("password", token)
    }

    // KT-XSS004: SSL errors swallowed
    fun onReceivedSslError(handler: SslErrorHandler) {
        handler.proceed()
    }
}

class NativeBridge
