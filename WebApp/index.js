import { UserSettings } from "./modules/userSettings.js";
import { USB } from './modules/com/usbSerial.js';
import { BT } from './modules/com/bluetooth.js';
import { UsbEsp32 } from './modules/com/usbEsp32.js';

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById('connectUsb').addEventListener('click', async () => {
        await USB.connect();
    });

    document.getElementById('connectBt').addEventListener('click', async () => {
        await BT.connect();
    });

    document.getElementById('connectOgxmW').addEventListener('click', async () => {
        await UsbEsp32.connect();
    });

    document.getElementById('button-replacePS4Keys').addEventListener('click', () => {
        document.getElementById('ps4-upload-form').classList.remove('hidden');
        document.getElementById('button-replacePS4Keys').classList.add('hidden');
    });
});