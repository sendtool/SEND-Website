// DES encryption/decryption implementation using CryptoJS

// DES encryption for text
function encryptTextDES(text, password) {
    const key = CryptoJS.enc.Utf8.parse(password);
    const encrypted = CryptoJS.DES.encrypt(text, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}

// DES decryption for text
function decryptTextDES(encryptedText, password) {
    const key = CryptoJS.enc.Utf8.parse(password);
    const decrypted = CryptoJS.DES.decrypt(encryptedText, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// Export functions for use in HTML pages
window.encryptTextDES = encryptTextDES;
window.decryptTextDES = decryptTextDES;
