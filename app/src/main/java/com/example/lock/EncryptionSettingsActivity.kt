package com.example.lock

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.CheckBox
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

class EncryptionSettingsActivity : AppCompatActivity() {

    private lateinit var rootView: View

    private lateinit var tilPassword: TextInputLayout
    private lateinit var tilConfirmPassword: TextInputLayout
    private lateinit var tilSecondZipPassword: TextInputLayout

    private lateinit var passwordInput: TextInputEditText
    private lateinit var confirmPasswordInput: TextInputEditText
    private lateinit var secondZipPasswordInput: TextInputEditText

    private lateinit var showPasswordCheckBox: CheckBox
    private lateinit var deleteCheckBox: CheckBox
    private lateinit var startBtn: Button

    private lateinit var cbJustFiles: MaterialCheckBox
    private lateinit var cbJustZip: MaterialCheckBox
    private lateinit var cbFilesAndZip: MaterialCheckBox
    private lateinit var cbDoubleZip: MaterialCheckBox

    private lateinit var zipOptionsContainer: View

    private fun <T : View> bindId(idName: String): T {
        val id = resources.getIdentifier(idName, "id", packageName)
        if (id == 0) {
            throw IllegalStateException("Missing view id: $idName")
        }
        return findViewById(id)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption_settings)

        rootView = findViewById(android.R.id.content)

        tilPassword = bindId("til_password")
        tilConfirmPassword = bindId("til_confirm_password")
        tilSecondZipPassword = bindId("til_second_zip_password")

        passwordInput = bindId("et_password")
        confirmPasswordInput = bindId("et_confirm_password")
        secondZipPasswordInput = bindId("et_second_zip_password")

        showPasswordCheckBox = bindId("cb_show_password")
        deleteCheckBox = bindId("cb_delete_after")
        startBtn = bindId("btn_start")

        cbJustFiles = bindId("cb_just_files")
        cbJustZip = bindId("cb_just_zip")
        cbFilesAndZip = bindId("cb_files_and_zip")
        cbDoubleZip = bindId("cb_double_zip")

        zipOptionsContainer = bindId("container_zip_options")

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()

        setupDefaultSelection()
        setupSingleChoiceMode()
        setupDoubleZipToggle()
        setupShowPasswordToggle()
        setupHideKeyboardOnBackgroundTap()
        clearErrorsOnInput()

        startBtn.setOnClickListener {
            hideKeyboard()

            val password = passwordInput.text?.toString()?.trim().orEmpty()
            val confirmPassword = confirmPasswordInput.text?.toString()?.trim().orEmpty()
            val secondZipPassword = secondZipPasswordInput.text?.toString()?.trim().orEmpty()

            tilPassword.error = null
            tilConfirmPassword.error = null
            tilSecondZipPassword.error = null

            if (password.isEmpty()) {
                tilPassword.error = "Please enter password"
                passwordInput.requestFocus()
                return@setOnClickListener
            }

            if (confirmPassword.isEmpty()) {
                tilConfirmPassword.error = "Please confirm password"
                confirmPasswordInput.requestFocus()
                return@setOnClickListener
            }

            if (password != confirmPassword) {
                tilConfirmPassword.error = "Passwords do not match"
                confirmPasswordInput.requestFocus()
                return@setOnClickListener
            }

            val encryptionType = when {
                cbDoubleZip.isChecked && cbJustZip.isChecked -> "DOUBLE_ZIP_JUST_ZIP"
                cbDoubleZip.isChecked && cbFilesAndZip.isChecked -> "DOUBLE_ZIP_FILES_AND_ZIP"
                cbFilesAndZip.isChecked -> "ZIP_FILES"
                cbJustZip.isChecked -> "JUST_ZIP"
                else -> "JUST_FILES"
            }

            val intent = Intent(this, ProcessingActivity::class.java)
            intent.putExtra("MODE", "ENCRYPT")
            intent.putStringArrayListExtra("FILES", selectedFiles)
            intent.putExtra("PASSWORD", password)
            intent.putExtra("SECOND_ZIP_PASSWORD", secondZipPassword)
            intent.putExtra("ENC_TYPE", encryptionType)
            intent.putExtra("DELETE_AFTER", deleteCheckBox.isChecked)
            startActivity(intent)
            finish()
        }
    }

    private fun setupDefaultSelection() {
        cbJustFiles.isChecked = true
        cbJustZip.isChecked = false
        cbFilesAndZip.isChecked = false
        cbDoubleZip.isChecked = false
        updateZipOptionsVisibility()
        updateSecondZipPasswordVisibility()
    }

    private fun setupSingleChoiceMode() {
        cbJustFiles.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                cbJustZip.isChecked = false
                cbFilesAndZip.isChecked = false
            } else if (!cbJustZip.isChecked && !cbFilesAndZip.isChecked) {
                cbJustFiles.isChecked = true
            }
            updateZipOptionsVisibility()
        }

        cbJustZip.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                cbJustFiles.isChecked = false
                cbFilesAndZip.isChecked = false
            } else if (!cbJustFiles.isChecked && !cbFilesAndZip.isChecked) {
                cbJustZip.isChecked = true
            }
            updateZipOptionsVisibility()
        }

        cbFilesAndZip.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                cbJustFiles.isChecked = false
                cbJustZip.isChecked = false
            } else if (!cbJustFiles.isChecked && !cbJustZip.isChecked) {
                cbFilesAndZip.isChecked = true
            }
            updateZipOptionsVisibility()
        }
    }

    private fun setupDoubleZipToggle() {
        cbDoubleZip.setOnCheckedChangeListener { _, _ ->
            updateSecondZipPasswordVisibility()
        }
    }

    private fun updateZipOptionsVisibility() {
        val shouldShow = cbJustZip.isChecked || cbFilesAndZip.isChecked
        zipOptionsContainer.visibility = if (shouldShow) View.VISIBLE else View.GONE

        if (!shouldShow) {
            cbDoubleZip.isChecked = false
        }

        updateSecondZipPasswordVisibility()
    }

    private fun updateSecondZipPasswordVisibility() {
        val shouldShow = zipOptionsContainer.visibility == View.VISIBLE && cbDoubleZip.isChecked
        tilSecondZipPassword.visibility = if (shouldShow) View.VISIBLE else View.GONE

        if (!shouldShow) {
            secondZipPasswordInput.text?.clear()
        }
    }

    private fun setupShowPasswordToggle() {
        showPasswordCheckBox.setOnCheckedChangeListener { _, isChecked ->
            val inputType = if (isChecked) {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }

            passwordInput.inputType = inputType
            confirmPasswordInput.inputType = inputType
            secondZipPasswordInput.inputType = inputType

            passwordInput.setSelection(passwordInput.text?.length ?: 0)
            confirmPasswordInput.setSelection(confirmPasswordInput.text?.length ?: 0)
            secondZipPasswordInput.setSelection(secondZipPasswordInput.text?.length ?: 0)
        }
    }

    private fun clearErrorsOnInput() {
        passwordInput.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) tilPassword.error = null
        }

        confirmPasswordInput.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) tilConfirmPassword.error = null
        }

        secondZipPasswordInput.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) tilSecondZipPassword.error = null
        }
    }

    private fun setupHideKeyboardOnBackgroundTap() {
        rootView.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_DOWN) {
                currentFocus?.clearFocus()
                hideKeyboard()
            }
            false
        }
    }

    private fun hideKeyboard() {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        val view = currentFocus ?: rootView
        imm?.hideSoftInputFromWindow(view.windowToken, 0)
    }
}