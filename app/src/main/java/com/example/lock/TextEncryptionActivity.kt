package com.example.lock

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.graphics.pdf.PdfDocument
import android.os.Bundle
import android.os.Environment
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import java.util.UUID
import java.io.File
import java.io.FileOutputStream
import com.example.lock.crypto.TextEncryptionEngine

class TextEncryptionActivity : AppCompatActivity() {

    private lateinit var mainTextBox: EditText
    private lateinit var inputPassword1: EditText
    private lateinit var inputPassword2: EditText
    private lateinit var btnCopy: Button
    private lateinit var btnPaste: Button
    private lateinit var btnClear: Button
    private lateinit var btnEncrypt: MaterialCardView
    private lateinit var btnDecrypt: MaterialCardView
    private lateinit var btnSave: MaterialCardView
    private lateinit var encryptionEngine: TextEncryptionEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_text_encryption)

        encryptionEngine = TextEncryptionEngine()

        initViews()
        setupListeners()
    }

    private fun initViews() {
        mainTextBox = findViewById(R.id.main_text_box)
        inputPassword1 = findViewById(R.id.input_password)
        inputPassword2 = findViewById(R.id.input_password_confirm)
        btnCopy = findViewById(R.id.btn_copy)
        btnPaste = findViewById(R.id.btn_paste)
        btnClear = findViewById(R.id.btn_clear)
        btnEncrypt = findViewById(R.id.btn_encrypt)
        btnDecrypt = findViewById(R.id.btn_decrypt)
        btnSave = findViewById(R.id.btn_save)
    }

    private fun setupListeners() {
        btnClear.setOnClickListener {
            mainTextBox.text.clear()
        }

        btnCopy.setOnClickListener {
            val textToCopy = mainTextBox.text.toString()
            if (textToCopy.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("EncryptedText", textToCopy)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            }
        }

        btnPaste.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard.hasPrimaryClip() && clipboard.primaryClip?.itemCount ?: 0 > 0) {
                val pastedText = clipboard.primaryClip?.getItemAt(0)?.text
                mainTextBox.setText(pastedText)
            }
        }

        btnEncrypt.setOnClickListener {
            processEncryptionAction(isEncrypt = true)
        }

        btnDecrypt.setOnClickListener {
            processEncryptionAction(isEncrypt = false)
        }

        btnSave.setOnClickListener {
            saveTextToPdf()
        }
    }

    private fun validatePasswords(): CharArray? {
        val pass1 = inputPassword1.text.toString()
        val pass2 = inputPassword2.text.toString()

        if (pass1.isEmpty() || pass2.isEmpty()) {
            Toast.makeText(this, "Password fields cannot be empty", Toast.LENGTH_SHORT).show()
            return null
        }

        if (pass1 != pass2) {
            Toast.makeText(this, "Passwords do not match", Toast.LENGTH_SHORT).show()
            return null
        }

        return pass1.toCharArray()
    }

    private fun processEncryptionAction(isEncrypt: Boolean) {
        val targetText = mainTextBox.text.toString()
        if (targetText.isEmpty()) {
            Toast.makeText(this, "Text box is empty", Toast.LENGTH_SHORT).show()
            return
        }

        val passwordChars = validatePasswords() ?: return

        try {
            if (isEncrypt) {
                val encryptedText = encryptionEngine.encrypt(targetText, passwordChars)
                mainTextBox.setText(encryptedText)
                Toast.makeText(this, "Encryption Successful", Toast.LENGTH_SHORT).show()
            } else {
                val decryptedText = encryptionEngine.decrypt(targetText, passwordChars)
                if (decryptedText != null) {
                    mainTextBox.setText(decryptedText)
                    Toast.makeText(this, "Decryption Successful", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Decryption Failed: Invalid key or data", Toast.LENGTH_LONG).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Process Error: ${e.message}", Toast.LENGTH_SHORT).show()
        } finally {
            passwordChars.fill('0')
            inputPassword1.text.clear()
            inputPassword2.text.clear()
        }
    }

    private fun saveTextToPdf() {
        val textToSave = mainTextBox.text.toString()
        if (textToSave.isEmpty()) {
            Toast.makeText(this, "Nothing to save", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            val pdfDocument = PdfDocument()
            val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()
            val page = pdfDocument.startPage(pageInfo)
            val canvas = page.canvas

            val textPaint = TextPaint().apply {
                color = Color.BLACK
                textSize = 14f
                isAntiAlias = true
            }

            val textWidth = pageInfo.pageWidth - 100
            val staticLayout = StaticLayout.Builder.obtain(textToSave, 0, textToSave.length, textPaint, textWidth)
                .setAlignment(Layout.Alignment.ALIGN_NORMAL)
                .setLineSpacing(0f, 1.2f)
                .setIncludePad(false)
                .build()

            canvas.translate(50f, 50f)
            staticLayout.draw(canvas)
            pdfDocument.finishPage(page)

            val rootDir = Environment.getExternalStorageDirectory()
            val encDir = File(rootDir, "ENC")

            if (!encDir.exists()) {
                val isCreated = encDir.mkdirs()
                if (!isCreated) {
                    Toast.makeText(this, "Failed to create ENC directory in root", Toast.LENGTH_SHORT).show()
                    pdfDocument.close()
                    return
                }
            }

            val fileName = UUID.randomUUID().toString().replace("-", "") + ".pdf"
            val pdfFile = File(encDir, fileName)

            FileOutputStream(pdfFile).use { outputStream ->
                pdfDocument.writeTo(outputStream)
            }

            Toast.makeText(this, "Saved to: ${pdfFile.absolutePath}", Toast.LENGTH_LONG).show()
            pdfDocument.close()

        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}