# mbx_secure_file
mbx_secure_file

# Document
https://www.canva.com/design/DAGnesDr6cs/D1TaAF7ens5sz2GRFIJrbQ/edit
# Use
final json = jsonEncode({
'email': 'demo@example.com',
'token': 'abc123',
});

const passphrase = 'isc_mobix_2025';

await MbxSecureFile.saveEncryptedData(json, passphrase);

final decrypted = await MbxSecureFile.readEncryptedData(passphrase);
print('Decrypted content: $decrypted');

# Contract
- Author: Nguyen Huu Nhan (NhanNH26)