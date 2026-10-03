// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Surface
import android.view.TextureView
import android.widget.Button
import android.widget.Toast

/**
 * The camera, until it sees a QR code; the text of the code is the result
 * (EXTRA_TEXT).  Camera2 straight, for no more libraries than ZXing's core:
 * the frames go to the preview and, in their brightness, to QrDecode.
 */
class ScanActivity : Activity() {

    companion object {
        const val EXTRA_TEXT = "text"
        private const val REQUEST_CAMERA = 1
    }

    private lateinit var preview: TextureView
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var asking = false
    @Volatile private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)
        preview = findViewById(R.id.preview)
        findViewById<Button>(R.id.cancel).setOnClickListener { finish() }
    }

    override fun onResume() {
        super.onResume()
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            if (!asking) {
                asking = true
                requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
            }
            return
        }
        thread = HandlerThread("n3n-scan").also { it.start() }
        handler = Handler(thread!!.looper)
        if (preview.isAvailable) {
            open()
        } else {
            preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                override fun onSurfaceTextureAvailable(st: SurfaceTexture, width: Int, height: Int) = open()
                override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, width: Int, height: Int) {}
                override fun onSurfaceTextureDestroyed(st: SurfaceTexture) = true
                override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
            }
        }
    }

    override fun onPause() {
        close()
        super.onPause()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, results: IntArray) {
        asking = false
        if (requestCode == REQUEST_CAMERA &&
            (results.isEmpty() || results[0] != PackageManager.PERMISSION_GRANTED)) {
            fail(R.string.scan_no_permission)
        }
        // when allowed, onResume() opens the camera
    }

    private fun fail(message: Int) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    /** The largest size of at most 1920x1080: enough for a code, little work */
    private fun chooseSize(sizes: Array<Size>): Size =
        sizes.filter { it.width * it.height <= 1920 * 1080 }.maxByOrNull { it.width * it.height } ?: sizes[0]

    @SuppressLint("MissingPermission")  // checked in onResume()
    private fun open() {
        val handler = handler ?: return
        val manager = getSystemService(CameraManager::class.java)
        try {
            val ids = manager.cameraIdList
            val id = ids.firstOrNull {
                manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) ==
                    CameraCharacteristics.LENS_FACING_BACK
            } ?: ids.firstOrNull()
            if (id == null) {
                fail(R.string.scan_no_camera)
                return
            }
            val map = manager.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            val sizes = map?.getOutputSizes(ImageFormat.YUV_420_888)
            if (sizes.isNullOrEmpty()) {
                fail(R.string.scan_no_camera)
                return
            }
            val size = chooseSize(sizes)

            reader = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2).also {
                it.setOnImageAvailableListener({ r -> onFrame(r) }, handler)
            }
            preview.surfaceTexture?.setDefaultBufferSize(size.width, size.height)
            fitPreview(size)

            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    startSession(device)
                }

                override fun onDisconnected(device: CameraDevice) {
                    device.close()
                    camera = null
                }

                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    camera = null
                    runOnUiThread { fail(R.string.scan_no_camera) }
                }
            }, handler)
        } catch (e: CameraAccessException) {
            fail(R.string.scan_no_camera)
        } catch (e: SecurityException) {
            fail(R.string.scan_no_permission)
        }
    }

    /** The activity is in portrait: the frames, wider than high, upright and not stretched */
    private fun fitPreview(size: Size) {
        val width = preview.width
        if (width > 0) {
            preview.layoutParams = preview.layoutParams.apply {
                height = width * maxOf(size.width, size.height) / minOf(size.width, size.height)
            }
        }
    }

    @Suppress("DEPRECATION")  // the List<Surface> variant is the one there is down to API 24
    private fun startSession(device: CameraDevice) {
        val texture = preview.surfaceTexture ?: return
        val target = reader?.surface ?: return
        val shown = Surface(texture)
        try {
            device.createCaptureSession(listOf(shown, target), object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    session = s
                    try {
                        val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                            addTarget(shown)
                            addTarget(target)
                            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                        }
                        s.setRepeatingRequest(request.build(), null, handler)
                    } catch (e: CameraAccessException) {
                        runOnUiThread { fail(R.string.scan_no_camera) }
                    } catch (e: IllegalStateException) {
                        // closed in the meantime
                    }
                }

                override fun onConfigureFailed(s: CameraCaptureSession) {
                    runOnUiThread { fail(R.string.scan_no_camera) }
                }
            }, handler)
        } catch (e: CameraAccessException) {
            fail(R.string.scan_no_camera)
        } catch (e: IllegalStateException) {
            // closed in the meantime
        }
    }

    /** On the camera's thread: the brightness (the Y plane) of the newest frame */
    private fun onFrame(r: ImageReader) {
        val image = try {
            r.acquireLatestImage()
        } catch (e: IllegalStateException) {
            null
        } ?: return
        try {
            if (done) {
                return
            }
            val plane = image.planes[0]
            val width = image.width
            val height = image.height
            val buffer = plane.buffer
            val y = ByteArray(width * height)
            for (row in 0 until height) {
                buffer.position(row * plane.rowStride)
                buffer.get(y, row * width, width)
            }
            val text = QrDecode.fromLuminance(y, width, height) ?: return
            done = true
            runOnUiThread {
                setResult(RESULT_OK, Intent().putExtra(EXTRA_TEXT, text))
                finish()
            }
        } finally {
            image.close()
        }
    }

    private fun close() {
        try {
            session?.close()
        } catch (e: IllegalStateException) {
        }
        session = null
        camera?.close()
        camera = null
        thread?.quitSafely()
        thread?.join()
        thread = null
        handler = null
        reader?.close()
        reader = null
    }
}
