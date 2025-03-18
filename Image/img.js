// Utility function to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
    const binary = new Uint8Array(buffer);
    let base64 = '';
    for (let i = 0; i < binary.length; i++) {
        base64 += String.fromCharCode(binary[i]);
    }
    return window.btoa(base64);
}

// Function to pad password to meet Triple DES key length requirement (24 bytes)
function padPassword(password) {
    let paddedPassword = password;
    while (paddedPassword.length < 24) {
        paddedPassword += password;
    }
    return paddedPassword.slice(0, 24);
}

// Function to show status message
function showStatus(message, isError = false) {
    const statusElement = document.getElementById('statusMessage');
    statusElement.textContent = message;
    statusElement.className = 'status-message ' + (isError ? 'error' : 'success');
    statusElement.style.display = 'block';
    
    // Hide the message after 3 seconds
    setTimeout(() => {
        statusElement.style.display = 'none';
    }, 3000);
}

// Main encryption function
function encryptButton() {
    const imageInput = document.getElementById('imageInput');
    const password = document.getElementById('passwordInput').value;
    const ciphertextOutput = document.getElementById('cipherTextOutput');

    // Validate inputs
    if (!imageInput.files[0]) {
        showStatus('Please select an image file', true);
        return;
    }
    if (!password) {
        showStatus('Please enter a password', true);
        return;
    }

    // File size validation (max 5MB)
    if (imageInput.files[0].size > 15 * 1024 * 1024) {
        showStatus('File size too large. Please choose a file under 15MB', true);
        return;
    }

    // Show loading status
    showStatus('Encrypting image...');
    
    const reader = new FileReader();
    
    reader.onload = function(event) {
        try {
            // Convert image data to base64
            const base64Data = arrayBufferToBase64(event.target.result);
            
            // Pad password and create encryption key
            const paddedPassword = padPassword(password);
            const key = CryptoJS.enc.Utf8.parse(paddedPassword);
            
            // Convert base64 to WordArray for encryption
            const wordArray = CryptoJS.enc.Base64.parse(base64Data);
            
            // Perform Triple DES encryption
            const encrypted = CryptoJS.TripleDES.encrypt(wordArray, key, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            });
            
            // Display encrypted result
            ciphertextOutput.value = encrypted.toString();
            showStatus('Encryption completed successfully');
        } catch (error) {
            console.error('Encryption error:', error);
            showStatus('Encryption failed. Please try again', true);
        }
    };

    reader.onerror = function(error) {
        console.error('File reading error:', error);
        showStatus('Error reading file. Please try again', true);
    };

    // Start reading the image file
    reader.readAsArrayBuffer(imageInput.files[0]);
}

// Updated function to copy encrypted text to clipboard
async function copyCipherText() {
    const ciphertextOutput = document.getElementById('cipherTextOutput');
    
    if (!ciphertextOutput.value) {
        showStatus('No text to copy', true);
        return;
    }

    try {
        // Use the modern clipboard API
        await navigator.clipboard.writeText(ciphertextOutput.value);
        showStatus('Text copied to clipboard!');
    } catch (err) {
        // Fallback for older browsers
        try {
            // Create a temporary textarea element
            const tempTextArea = document.createElement('textarea');
            tempTextArea.value = ciphertextOutput.value;
            document.body.appendChild(tempTextArea);
            
            // Select and copy the text
            tempTextArea.select();
            document.execCommand('copy');
            
            // Clean up
            document.body.removeChild(tempTextArea);
            
            showStatus('Text copied to clipboard!');
        } catch (fallbackErr) {
            console.error('Failed to copy text:', fallbackErr);
            showStatus('Failed to copy text', true);
        }
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // File input change handler
    const fileInput = document.querySelector('.custom-file-upload input[type="file"]');
    const imageInput = document.getElementById('imageInput');
    const imageNameOutput = document.getElementById('imageNameOutput');

    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files[0]) {
                // Update hidden input
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(this.files[0]);
                imageInput.files = dataTransfer.files;
                
                // Display file name
                imageNameOutput.textContent = this.files[0].name;
            } else {
                imageNameOutput.textContent = '';
            }
        });
    }

    // Initialize encryption button handler
    const encryptBtn = document.getElementById('encryptButton');
    if (encryptBtn) {
        encryptBtn.addEventListener('click', encryptButton);
    }

    // Add keypress handler for password input
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                encryptButton();
            }
        });
    }

    // Add event listener for paste from clipboard
    const cipherTextOutput = document.getElementById('cipherTextOutput');
    if (cipherTextOutput) {
        cipherTextOutput.addEventListener('paste', (e) => {
            e.preventDefault();
            const text = e.clipboardData.getData('text');
            e.target.value = text;
        });
    }

    // Add event listener for the copy button
    const copyButton = document.querySelector('.copy-button');
    if (copyButton) {
        copyButton.addEventListener('click', copyCipherText);
    }
});

// Decryption functionality
let isDecrypting = false;

function showError(message) {
    const errorElement = document.getElementById('errorMessage');
    errorElement.textContent = message;
    errorElement.style.display = 'block';
    setTimeout(() => {
        errorElement.style.display = 'none';
    }, 5000);
}

function setLoadingState(loading) {
    const button = document.getElementById('decryptButton');
    const spinner = document.getElementById('loadingSpinner');
    const buttonText = document.getElementById('decryptButtonText');
    
    isDecrypting = loading;
    button.disabled = loading;
    spinner.style.display = loading ? 'block' : 'none';
    buttonText.textContent = loading ? 'Decrypting...' : 'Decrypt';
}

function validateInput(cipherText, password) {
    if (!cipherText.trim()) {
        throw new Error('Please enter the encrypted cipher text');
    }
    if (!password.trim()) {
        throw new Error('Please enter the decryption password');
    }
}

async function decryptImage() {
    if (isDecrypting) return;

    const cipherText = document.getElementById('cipherTextInput').value;
    const password = document.getElementById('passwordInput').value;
    const decryptedImageContainer = document.getElementById('decryptedImageContainer');
    const downloadButton = document.getElementById('downloadButton');

    try {
        validateInput(cipherText, password);
        setLoadingState(true);

        // Use the same padding method as encryption
        const paddedPassword = padPassword(password);
        const key = CryptoJS.enc.Utf8.parse(paddedPassword);

        // Parse the ciphertext to handle both string and direct formats
        let cipherParams;
        try {
            // Try parsing as Base64
            const cipherBlob = CryptoJS.enc.Base64.parse(cipherText);
            cipherParams = CryptoJS.lib.CipherParams.create({
                ciphertext: cipherBlob
            });
        } catch (e) {
            // If not Base64, use as-is
            cipherParams = cipherText;
        }

        // Decrypt using the same Triple DES configuration
        const decrypted = CryptoJS.TripleDES.decrypt(
            cipherParams,
            key,
            {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            }
        );

        // Convert decrypted WordArray to Base64
        let decryptedBase64;
        try {
            // First, try direct Base64 conversion
            decryptedBase64 = decrypted.toString(CryptoJS.enc.Base64);
            if (!decryptedBase64) throw new Error('Empty result from Base64 conversion');
        } catch (e) {
            // If that fails, try converting through binary first
            const words = decrypted.words;
            const sigBytes = decrypted.sigBytes;
            const bytes = new Uint8Array(sigBytes);
            
            for (let i = 0; i < sigBytes; i++) {
                const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                bytes[i] = byte;
            }
            
            let binary = '';
            bytes.forEach(byte => {
                binary += String.fromCharCode(byte);
            });
            decryptedBase64 = window.btoa(binary);
        }

        if (!decryptedBase64) {
            throw new Error('Decryption produced no valid data');
        }

        // Create and verify image
        const imageDataUrl = `data:image/png;base64,${decryptedBase64}`;
        const img = new Image();
        
        await new Promise((resolve, reject) => {
            img.onload = resolve;
            img.onerror = () => reject(new Error('Decrypted data is not a valid image'));
            img.src = imageDataUrl;
        });

        // Display the decrypted image
        document.getElementById('decryptedImage').src = imageDataUrl;
        decryptedImageContainer.style.display = 'block';
        downloadButton.href = imageDataUrl;
        downloadButton.style.display = 'inline-block';

    } catch (error) {
        console.error('Decryption error:', error);
        showError(error.message || 'Decryption failed. Please verify your inputs.');
        decryptedImageContainer.style.display = 'none';
        downloadButton.style.display = 'none';
    } finally {
        setLoadingState(false);
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // File input change handler
    const fileInput = document.querySelector('.custom-file-upload input[type="file"]');
    const imageInput = document.getElementById('imageInput');
    const imageNameOutput = document.getElementById('imageNameOutput');

    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files[0]) {
                // Update hidden input
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(this.files[0]);
                imageInput.files = dataTransfer.files;
                
                // Display file name
                imageNameOutput.textContent = this.files[0].name;
            } else {
                imageNameOutput.textContent = '';
            }
        });
    }

    // Initialize encryption button handler
    const encryptBtn = document.getElementById('encryptButton');
    if (encryptBtn) {
        encryptBtn.addEventListener('click', encryptButton);
    }

    // Initialize decryption event listeners
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                decryptImage();
            }
        });
    }

    // Clear error on input
    ['cipherTextInput', 'passwordInput'].forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('input', () => {
                const errorMessage = document.getElementById('errorMessage');
                if (errorMessage) {
                    errorMessage.style.display = 'none';
                }
            });
        }
    });
});

function handleFileSelect(event) {
    const file = event.target.files[0];
    const fileInfo = document.getElementById('fileInfo');
    
    if (!fileInfo) return;
    
    const fileName = fileInfo.querySelector('.file-name');
    const fileSize = fileInfo.querySelector('.file-size');

    if (file) {
        if (file.size > MAX_FILE_SIZE) {
            alert(`File is too large. Maximum size allowed is ${formatFileSize(MAX_FILE_SIZE)}`);
            event.target.value = '';
            fileInfo.style.display = 'none';
            return;
        }

        fileName.textContent = file.name;
        fileSize.textContent = 'Size: ' + formatFileSize(file.size);
        fileInfo.style.display = 'block';
    } else {
        fileInfo.style.display = 'none';
    }
}