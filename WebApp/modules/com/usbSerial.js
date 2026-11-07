import { USBInterface } from "./usbInterface.js";
import { Gamepad } from "../gamepad.js";
import { UI } from "../uiSettings.js";
import { UserSettings } from "../userSettings.js";

class USBManager {
    static #PACKET_LENGTH = Object.freeze(64);
    static #HEADER_LENGTH = Object.freeze(9);
    static #BAUDRATE = Object.freeze(9600); 
    static #BUFFER_LEN = Object.freeze(1024);

    static #PACKET_ID = Object.freeze({
        NONE: 0,
        GET_PROFILE_BY_ID: 0x50,
        GET_PROFILE_BY_IDX: 0x55,
        SET_PROFILE_START: 0x60,
        SET_PROFILE: 0x61,
        PS4_KEYS_UPLOAD: 0x70,
        PS4_KEYS_STATUS: 0x71,
        PS4_KEYS_QUERY: 0x72,
        PS4_KEYS_PRESENT: 0x73,
        SET_GP_IN: 0x80,
        SET_GP_OUT: 0x81,
        RESP_ERROR: 0xFF
    });

    static #PACKET_HEADER = Object.freeze([
        { key: "packetLen",   size: 1 },
        { key: "packetId",    size: 1 },
        { key: "deviceMode",  size: 1 },
        { key: "maxGamepads", size: 1 },
        { key: "playerIdx",   size: 1 },
        { key: "profileId",   size: 1 },
        { key: "chunksTotal", size: 1 },
        { key: "chunkIdx",    size: 1 },
        { key: "chunkLen",    size: 1 },
    ]);

    #interface = null;
    #currentBufferInOffset = 0;
    #ps4StatusFromDevice = false;
    #ps4RebootPending = false;
    #bufferIn = null;
    #userSettings = null;

    constructor() {
        this.#interface = new USBInterface();
        this.#bufferIn = new Uint8Array(USBManager.#BUFFER_LEN);
    }

    async init(userSettings) {
        try {
            this.#userSettings = userSettings;

            if (await this.#interface.connect(USBManager.#BAUDRATE)) {
                this.#interface.registerDisconnectCb(() => {
                    // After a successful PS4 key upload the firmware saves to flash and reboots,
                    // which drops the port. Show what happened instead of reloading silently.
                    if (this.#ps4RebootPending) {
                        alert("PS4 keys verified and saved. The adapter rebooted into PS4 output mode.");
                        window.location.reload();
                        return;
                    }
                    const errorBox = document.getElementById("errorTxt");
                    if (errorBox) {
                        errorBox.textContent = "USB connection closed. Open the browser console (F12) for details.";
                        errorBox.classList.remove("hidden");
                    }
                });

                this.#interface.readTask(USBManager.#PACKET_LENGTH, this.#processPacketIn.bind(this));
                await this.#sleep(1000);
                return true;
            }
        } catch (error) {
            console.warn('Connection error:', error);
            await this.#interface.disconnect();
            return false;
        }
    }

    async saveProfile() {
        let header = this.#headerFromUi(USBManager.#PACKET_ID.SET_PROFILE_START);
        await this.#writeToDevice(
            header, 
            new Uint8Array([0xFF])
        );
        await this.#sleep(100);

        const data = this.#userSettings.getProfileBytes();
        header.packetId = USBManager.#PACKET_ID.SET_PROFILE;
        await this.#writeToDevice(
            header, 
            data
        );
    }

    async uploadPS4Keys(privateKeyFile, signatureFile, serialFile) {
        if (!privateKeyFile || !signatureFile || !serialFile)
            throw new Error("Select all three files: private key, signature, and serial number.");
        const pem = await privateKeyFile.text();
        const der = USBManager.#pemToDer(pem);
        const rsa = USBManager.#extractRsaPrivateKey(der);
        const signature = new Uint8Array(await signatureFile.arrayBuffer());
        if (signature.length !== 256) throw new Error("Signature file must be exactly 256 bytes.");
        const serialText = (await serialFile.text()).trimEnd();
        if (!/^[0-9a-fA-F]{1,16}$/.test(serialText))
            throw new Error("Serial file must contain up to 16 hexadecimal characters.");
        const serialHex = serialText.padStart(32, "0");
        const serial = Uint8Array.from(serialHex.match(/../g), byte => parseInt(byte, 16));
        const parts = [serial, signature,
            USBManager.#bigIntToMbedBytes(rsa.n, 256),
            USBManager.#bigIntToMbedBytes(rsa.e, 4),
            USBManager.#bigIntToMbedBytes(rsa.p, 128),
            USBManager.#bigIntToMbedBytes(rsa.q, 128)];
        const bundle = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
        let offset = 0;
        parts.forEach(part => { bundle.set(part, offset); offset += part.length; });
        // Device status packets can arrive while we are still writing; don't overwrite them.
        this.#ps4StatusFromDevice = false;
        await this.#writeToDevice(
            this.#headerFromUi(USBManager.#PACKET_ID.PS4_KEYS_UPLOAD),
            bundle,
            (sent, total) => {
                if (!this.#ps4StatusFromDevice)
                    document.getElementById("ps4-auth-status").textContent = `Sending key data… ${sent}/${total}`;
            },
            20
        );
        if (!this.#ps4StatusFromDevice)
            document.getElementById("ps4-auth-status").textContent = "Sent key data; waiting for device…";
    }

    static #pemToDer(pem) {
        const base64 = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
        if (!base64) throw new Error("Private key PEM file is empty or invalid.");
        return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
    }

    static #extractRsaPrivateKey(der) {
        let keyDer = der;
        const readNode = (bytes, offset) => {
            if (offset + 2 > bytes.length) throw new Error("Invalid RSA private key DER.");
            const tag = bytes[offset++];
            let length = bytes[offset++];
            if (length & 0x80) {
                const count = length & 0x7f;
                if (!count || count > 4 || offset + count > bytes.length) throw new Error("Invalid RSA key DER length.");
                length = 0;
                for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
            }
            const end = offset + length;
            if (end > bytes.length) throw new Error("Truncated RSA private key DER.");
            return { tag, start: offset, end, next: end };
        };
        const children = (bytes, seq) => {
            const result = [];
            for (let at = seq.start; at < seq.end;) {
                const node = readNode(bytes, at);
                result.push(node);
                at = node.next;
            }
            return result;
        };
        let root = readNode(der, 0);
        if (root.tag !== 0x30) throw new Error("Unsupported private key format; expected RSA PEM.");
        let nodes = children(der, root);
        // PKCS#8 wraps the PKCS#1 RSA key in an OCTET STRING.
        if (nodes[2]?.tag === 0x04) {
            const wrapped = der.subarray(nodes[2].start, nodes[2].end);
            keyDer = wrapped;
            root = readNode(wrapped, 0);
            if (root.tag !== 0x30) throw new Error("Invalid PKCS#8 RSA private key.");
            nodes = children(wrapped, root);
        }
        if (nodes.length < 9 || nodes[0].tag !== 0x02)
            throw new Error("Could not parse RSA private key; use a PKCS#1 or PKCS#8 RSA PEM.");
        const integer = node => {
            let start = node.start;
            while (start < node.end - 1 && keyDer[start] === 0) start++;
            let value = 0n;
            for (let i = start; i < node.end; i++) value = (value << 8n) | BigInt(keyDer[i]);
            return value;
        };
        return { n: integer(nodes[1]), e: integer(nodes[2]), p: integer(nodes[4]), q: integer(nodes[5]) };
    }

    static #bigIntToMbedBytes(value, length) {
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length && value > 0n; i++, value >>= 8n)
            bytes[i] = Number(value & 0xffn);
        if (value > 0n) throw new Error("RSA key component exceeds supported size.");
        return bytes;
    }

    async queryPS4Keys() {
        await this.#writeToDevice(
            this.#headerFromUi(USBManager.#PACKET_ID.PS4_KEYS_QUERY),
            new Uint8Array([0xFF])
        );
    }

    async getProfileById() {
        let header = this.#headerFromUi(USBManager.#PACKET_ID.GET_PROFILE_BY_ID);
        await this.#writeToDevice(
            header, 
            new Uint8Array([0xFF])
        );
    }

    async getProfileByIdx() {
        let header = this.#headerFromUi(USBManager.#PACKET_ID.GET_PROFILE_BY_IDX);
        await this.#writeToDevice(
            header, 
            new Uint8Array([0xFF])
        );
    }

    async disconnect() {
        await this.#interface.disconnect();
    }

    #headerFromUi(packetId) {
        return {
            packetLen: USBManager.#PACKET_LENGTH,
            packetId: packetId,
            deviceMode: UI.getSelectedDeviceMode(),
            maxGamepads: this.#userSettings.maxGamepads,
            playerIdx: UI.getSelectedPlayerIdx(),
            profileId: UI.getSelectedProfileId(),
            chunksTotal: 1,
            chunkIdx: 0,
            chunkLen: 0
        }
    }

    #deserializeHeader(packetData) {
        if (packetData.length < USBManager.#HEADER_LENGTH) {
            console.error("Invalid packet data length.");
            return;
        }
        const header = {};
        let offset = 0;
        USBManager.#PACKET_HEADER.forEach(field => {
            header[field.key] = packetData[offset];
            offset += field.size;
        });
        return header;
    }

    #serializeHeader(header) {
        const buffer = new Uint8Array(USBManager.#HEADER_LENGTH);
        let offset = 0;
        USBManager.#PACKET_HEADER.forEach(field => {
            buffer[offset] = header[field.key];
            offset += field.size;
        });
        return buffer;
    }

    #processPacketInData(header, bufferIn, dataLen) {
        switch (header.packetId) {
            case USBManager.#PACKET_ID.GET_PROFILE_BY_IDX:   
                console.log("Received profile data.");
                this.#userSettings.setProfileFromBytes(bufferIn.subarray(0, dataLen));
                this.#userSettings.maxGamepads = header.maxGamepads;
                this.#userSettings.playerIdx = header.playerIdx;
                this.#userSettings.deviceMode = header.deviceMode;
                UI.updateAll(this.#userSettings);
                break;

            case USBManager.#PACKET_ID.GET_PROFILE_BY_ID:
                console.log("Received profile data.");
                this.#userSettings.setProfileFromBytes(bufferIn.subarray(0, dataLen));
                this.#userSettings.maxGamepads = header.maxGamepads;
                this.#userSettings.deviceMode = header.deviceMode;
                UI.updateAll(this.#userSettings);
                break; 

            case USBManager.#PACKET_ID.SET_GP_IN:
                const gamepad = new Gamepad();
                gamepad.setReportFromBytes(bufferIn.subarray(0, dataLen));
                UI.drawGamepadInput(gamepad, this.#userSettings);
                break;

            case USBManager.#PACKET_ID.PS4_KEYS_PRESENT: {
                const valid = bufferIn[0] === 1;
                const el = document.getElementById("ps4-keys-present");
                if (el) {
                    el.textContent = valid
                        ? "PS4 keys: installed and valid"
                        : "PS4 keys: not installed or invalid";
                }
                // Show the upload form only when there are no valid keys.
                document.getElementById("ps4-upload-form").classList.toggle("hidden", valid);
                document.getElementById("button-replacePS4Keys").classList.toggle("hidden", !valid);
                break;
            }

            case USBManager.#PACKET_ID.PS4_KEYS_STATUS:
                this.#ps4StatusFromDevice = true;
                this.#ps4RebootPending = bufferIn[0] === 2;
                document.getElementById("ps4-auth-status").textContent = bufferIn[0] === 3
                    ? "Device received the upload; receiving remaining data…"
                    : bufferIn[0] === 2
                        ? "Keys verified; saving to flash and rebooting the adapter…"
                        : bufferIn[0] === 1
                            ? "Keys installed. Restart into PS4 output mode to use them."
                            : "Key upload rejected: incomplete data or invalid RSA key. Check the three files and try again.";
                break;

            default:
                console.warn(`Unknown packet ID: ${header.packetId}`);
                break;
        }
    }

    #processPacketIn(data) {
        if (data[0] !== USBManager.#PACKET_LENGTH) {
            console.warn(`Invalid packet length: ${data[0]}`);
            return;
        }
        const header = this.#deserializeHeader(data);

        this.#bufferIn.set(
            data.subarray(
                USBManager.#HEADER_LENGTH, 
                USBManager.#HEADER_LENGTH + header.chunkLen
            ), this.#currentBufferInOffset
        );

        this.#currentBufferInOffset += header.chunkLen;

        console.log("Received packet: " + (header.chunkIdx + 1) + " of " + header.chunksTotal);    

        if (header.chunkIdx + 1 === header.chunksTotal) {
            this.#processPacketInData(header, this.#bufferIn, this.#currentBufferInOffset);
            this.#currentBufferInOffset = 0;
        }
    }

    async #writeToDevice(header, data, onProgress = null, interPacketDelayMs = 0) {
        const dataLen = data.length;
        const lenLimit = USBManager.#PACKET_LENGTH - USBManager.#HEADER_LENGTH;
        const chunksTotal = Math.ceil(dataLen / lenLimit);;
        let currentOffset = 0;

        header.chunksTotal = chunksTotal;

        for (let i = 0; i < chunksTotal; i++) {
            const isLastChunk = (i === chunksTotal - 1);
            const chunkLen = isLastChunk ? dataLen - currentOffset : lenLimit;
            header.chunkIdx = i;
            header.chunkLen = chunkLen;

            const buffer = new Uint8Array(USBManager.#PACKET_LENGTH);

            buffer.set(this.#serializeHeader(header), 0);
            buffer.set(
                data.subarray(currentOffset, currentOffset + chunkLen), 
                USBManager.#HEADER_LENGTH
            );

            console.log("Writing packet: " + (i + 1) + " of " + chunksTotal);

            await this.#interface.write(buffer);
            currentOffset += chunkLen;
            onProgress?.(i + 1, chunksTotal);
            if (interPacketDelayMs > 0 && !isLastChunk) await this.#sleep(interPacketDelayMs);
        }
    }

    async #sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

export const USB = {

    async connect() {
        if (!("serial" in navigator)) {
            console.error("Web Serial API not supported.");
            return;
        }

        const userSettings = new UserSettings();
        UI.init(userSettings);
        const usbManager = new USBManager();

        try {
            UI.connectButtonsEnabled(false);

            if (!(await usbManager.init(userSettings))) {
                throw new Error("Connection failed.");
            }

            await usbManager.getProfileByIdx();
            await usbManager.queryPS4Keys();

            UI.updateAll(userSettings);
            UI.toggleConnected(true);
            UI.setSubheaderText("Settings");

            UI.addCallbackLoadProfile(async () => {
                await usbManager.getProfileById();
                UI.updateAll(userSettings);
            }, userSettings);

            UI.addCallbackSaveProfile(async () => {
                await usbManager.saveProfile();
            }, userSettings);

            UI.addCallbackDisconnect(async () => {
                await usbManager.disconnect();
                UI.toggleConnected(false);
                window.location.reload();
            });

            document.getElementById("button-uploadPS4Keys").addEventListener("click", async () => {
                const status = document.getElementById("ps4-auth-status");
                try {
                    status.textContent = "Installing keys…";
                    await usbManager.uploadPS4Keys(
                        document.getElementById("ps4-private-key-file").files[0],
                        document.getElementById("ps4-signature-file").files[0],
                        document.getElementById("ps4-serial-file").files[0]
                    );
                } catch (error) {
                    status.textContent = error.message;
                }
            });

            document.getElementById("button-replacePS4Keys")?.addEventListener("click", () => {
                document.getElementById("ps4-upload-form").classList.remove("hidden");
                document.getElementById("button-replacePS4Keys").classList.add("hidden");
            });

        } catch (error) {
            console.warn('Connection error:', error);
            await usbManager.disconnect();
            // Show the failure on the page instead of silently reloading.
            const errorBox = document.getElementById("errorTxt");
            if (errorBox) {
                errorBox.textContent = `USB connection failed: ${error?.message || error}`;
                errorBox.classList.remove("hidden");
            } else {
                alert(`USB connection failed: ${error?.message || error}`);
            }
            UI.connectButtonsEnabled(true);
        }
    }
};
