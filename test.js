const { encrypt, decrypt } = require('./script');

// Example payload (could be user data)
const userPayload = {
  id: '20210206',
  email: 'saanvisujaykiran@gmail.com',
};

// Step 1: Encrypt the payload
const token = encrypt(userPayload);

// Step 2: Decrypt it back
const decodedPayload = decrypt(token);

// Step 3: Verify it worked
if (decodedPayload && decodedPayload.email === userPayload.email) {
  console.log('✅ Success');
} else {
  console.log('❌ Failed');
}
