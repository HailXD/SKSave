document.addEventListener('DOMContentLoaded', () => {
    const dataType = document.getElementById('dataType');
    const base64Input = document.getElementById('base64Input');
    const decodeButton = document.getElementById('decodeButton');
    const encodeButton = document.getElementById('encodeButton');
    const jsonEditor = document.getElementById('jsonEditor');
    const base64Output = document.getElementById('base64Output');
    const outputDiv = document.getElementById('output');

    let selectedDataType = 'default';

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
    
    function getHandler(dataType) {
        switch (dataType) {
            case 'statistic':
                return ["des", KEY_STATISTIC];
            case 'game':
                return ["xor", KEY_XOR];
            case 'item_data':
                return ["des", KEY_DEFAULT]; // Assuming item_data uses default DES
            case 'default':
            default:
                return ["des", KEY_DEFAULT];
        }
    }

    decodeButton.addEventListener('click', () => {
        const base64Content = base64Input.value.trim();
        selectedDataType = dataType.value;

        if (!base64Content) {
            alert("Please paste the Base64 content.");
            return;
        }

        const [handlerType, key] = getHandler(selectedDataType);

        let decryptedContent;
        if (handlerType === 'des') {
            decryptedContent = decryptDes(base64Content, key, IV);
        } else { // xor
            try {
                const binaryString = atob(base64Content);
                const arrayBuffer = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    arrayBuffer[i] = binaryString.charCodeAt(i);
                }
                const xorResult = xorCipher(arrayBuffer, key);
                decryptedContent = new TextDecoder("utf-8").decode(xorResult);
            } catch (e) {
                console.error("Error decoding base64 or decrypting XOR:", e);
                decryptedContent = null;
            }
        }

        if (decryptedContent) {
            try {
                const jsonObj = JSON.parse(decryptedContent);
                jsonEditor.value = JSON.stringify(jsonObj, null, 4);
                outputDiv.textContent = `Successfully decoded ${selectedDataType} data.`;
            } catch (err) {
                outputDiv.textContent = "Failed to parse JSON from decrypted content.";
                console.error(err);
            }
        } else {
            outputDiv.textContent = "Failed to decrypt the file.";
        }
    });

    encodeButton.addEventListener('click', () => {
        selectedDataType = dataType.value; // Update data type on encode
        let jsonContent;
        try {
            jsonContent = JSON.parse(jsonEditor.value);
        } catch (e) {
            alert("Invalid JSON in the editor.");
            return;
        }
        
        const contentStr = JSON.stringify(jsonContent);
        
        const [handlerType, key] = getHandler(selectedDataType);

        let encryptedBase64;
        if (handlerType === 'des') {
            encryptedBase64 = encryptDes(contentStr, key, IV);
        } else { // xor
            const encoder = new TextEncoder();
            const data = encoder.encode(contentStr);
            const xorResult = xorCipher(data, key);
            let binaryString = '';
            for (let i = 0; i < xorResult.length; i++) {
                binaryString += String.fromCharCode(xorResult[i]);
            }
            encryptedBase64 = btoa(binaryString);
        }

        if (encryptedBase64) {
            base64Output.value = encryptedBase64;
            outputDiv.textContent = `Successfully encoded ${selectedDataType} data.`;
        } else {
            outputDiv.textContent = 'Encoding failed.';
        }
    });
});
