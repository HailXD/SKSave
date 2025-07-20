document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const decodeButton = document.getElementById('decodeButton');
    const encodeButton = document.getElementById('encodeButton');
    const jsonEditor = document.getElementById('jsonEditor');
    const downloadLink = document.getElementById('downloadLink');
    const outputDiv = document.getElementById('output');

    let originalFilename = '';

    const KEY_STATISTIC = CryptoJS.enc.Utf8.parse('crst1\0\0\0');
    const KEY_DEFAULT = CryptoJS.enc.Utf8.parse('iambo\0\0\0');
    const IV = CryptoJS.enc.Utf8.parse('Ahbool\0\0');
    const KEY_XOR = [115, 108, 99, 122, 125, 103, 117, 99, 127, 87, 109, 108, 107, 74, 95];

    function xorCipher(data, key) {
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ key[i % key.length];
        }
        return result;
    }

    function decryptDes(data, key, iv) {
        try {
            const decodedData = CryptoJS.enc.Base64.parse(data);
            const decrypted = CryptoJS.DES.decrypt({ ciphertext: decodedData }, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            return decrypted.toString(CryptoJS.enc.Utf8);
        } catch (e) {
            console.error("Error decrypting with DES:", e);
            return null;
        }
    }

    function encryptDes(data, key, iv) {
        const encrypted = CryptoJS.DES.encrypt(data, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    }
    
    function getFileHandler(filename) {
        if (filename.startsWith("statistic")) {
            return ["des", KEY_STATISTIC];
        }
        if (filename === "game.data") {
            return ["xor", KEY_XOR];
        }
        return ["des", KEY_DEFAULT];
    }

    decodeButton.addEventListener('click', () => {
        const file = fileInput.files[0];
        if (!file) {
            alert("Please select a file first.");
            return;
        }

        originalFilename = file.name;
        const reader = new FileReader();

        reader.onload = (e) => {
            const content = e.target.result;
            let cleanFilename = originalFilename.split("_")[0] + ".data";
            if (originalFilename.includes("item_data")) {
                 cleanFilename = "item_data.data";
            }
            
            const [handlerType, key] = getFileHandler(cleanFilename);

            let decryptedContent;
            if (handlerType === 'des') {
                decryptedContent = decryptDes(content, key, IV);
            } else { // xor
                const arrayBuffer = new Uint8Array(content.split("").map(c => c.charCodeAt(0)));
                const xorResult = xorCipher(arrayBuffer, key);
                decryptedContent = new TextDecoder("utf-8").decode(xorResult);
            }

            if (decryptedContent) {
                try {
                    const jsonObj = JSON.parse(decryptedContent);
                    jsonEditor.value = JSON.stringify(jsonObj, null, 4);
                    outputDiv.textContent = `Successfully decoded ${originalFilename}.`;
                } catch (err) {
                    outputDiv.textContent = "Failed to parse JSON from decrypted content.";
                    console.error(err);
                }
            } else {
                outputDiv.textContent = "Failed to decrypt the file.";
            }
        };
        
        const [handlerType, _] = getFileHandler(originalFilename.split("_")[0] + ".data");
        if(handlerType === 'des') {
            reader.readAsText(file);
        } else {
            reader.readAsBinaryString(file);
        }
    });

    encodeButton.addEventListener('click', () => {
        if (!originalFilename) {
            alert("You need to decode a file first to set the filename.");
            return;
        }

        let jsonContent;
        try {
            jsonContent = JSON.parse(jsonEditor.value);
        } catch (e) {
            alert("Invalid JSON in the editor.");
            return;
        }
        
        const contentStr = JSON.stringify(jsonContent);

        let cleanFilename = originalFilename.split("_")[0] + ".data";
        if (originalFilename.includes("item_data")) {
             cleanFilename = "item_data.data";
        }
        const [handlerType, key] = getFileHandler(cleanFilename);

        let encryptedContent;
        if (handlerType === 'des') {
            encryptedContent = encryptDes(contentStr, key, IV);
        } else { // xor
            const encoder = new TextEncoder();
            const data = encoder.encode(contentStr);
            const xorResult = xorCipher(data, key);
            encryptedContent = new Blob([xorResult], {type: 'application/octet-stream'});
        }
        
        if (encryptedContent) {
            const blob = (handlerType === 'des') ? new Blob([encryptedContent], { type: 'text/plain' }) : encryptedContent;
            downloadLink.href = URL.createObjectURL(blob);
            downloadLink.download = originalFilename;
            downloadLink.textContent = `Click to download ${originalFilename}`;
            downloadLink.style.display = 'block';
            outputDiv.textContent = `Successfully encoded. Ready for download.`;
        } else {
            outputDiv.textContent = 'Encoding failed.';
        }
    });
});