const crypto = require('crypto'); // ✅ correct Node.js built-in module
const jwt = require('jsonwebtoken');

const SECRET = 'my_jwt_secret'; // Used to sign/verify JWT
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes key for AES-256 encryption
const IV_LENGTH = 16; // AES needs a random 16-byte IV


const encrypt = (payload) => {
  try {
    // 1. Create a JWT with your payload
    const token = jwt.sign(payload, SECRET, { expiresIn: '1h' });

    // 2. Create a random IV
    const iv = crypto.randomBytes(IV_LENGTH);

    // 3. Create a cipher with AES encryption
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);

    // 4. Encrypt the JWT token
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // 5. Combine the IV + encrypted string (IV is needed for decryption)
    const encryptedData = iv.toString('hex') + ':' + encrypted;

    console.log('Encrypted Token:', encryptedData);
    return encryptedData;
  } catch (err) {
    console.error('Encryption error:', err);
  }
};


const decrypt = (encryptedData) => {
  try {
    // 1. Split IV and encrypted token
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');

    // 2. Create a decipher with same key and IV
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);

    // 3. Decrypt it back into the JWT string
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // 4. Verify the JWT and get back original payload
    const payload = jwt.verify(decrypted, SECRET);

    console.log('Decrypted Payload:', payload);
    return payload;
  } catch (err) {
    console.error('Decryption error:', err);
  }
};


module.exports = {
  encrypt,
  decrypt
}
