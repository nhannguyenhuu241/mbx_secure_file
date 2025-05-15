# mbx_secure_file
mbx_secure_file

# Use
final json = jsonEncode({
'email': 'demo@example.com',
'token': 'abc123',
});

const passphrase = 'contract author';

await MbxSecureFile.saveEncryptedData(json, passphrase);

final decrypted = await MbxSecureFile.readEncryptedData(passphrase);
print('Decrypted content: $decrypted');

# Contact
- Author: Nguyen Huu Nhan (NhanNH26)