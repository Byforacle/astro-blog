// 加密函数
export async function encrypt(text: string, password: string): Promise<string> {
  const key = password.length >= 16 ? password.slice(0, 16) : password.padEnd(16, '0');
  const iv = crypto.getRandomValues(new Uint8Array(16));
  
  const keyBuffer = new TextEncoder().encode(key);
  const textBuffer = new TextEncoder().encode(text);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-CBC', length: 128 },
    false,
    ['encrypt']
  );
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    textBuffer
  );
  
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  
  // 处理大数据时避免调用栈溢出
  let binary = '';
  for (let i = 0; i < combined.length; i++) {
    binary += String.fromCharCode(combined[i]);
  }
  return btoa(binary);
}

// 解密函数
export async function decrypt(encryptedData: string, password: string): Promise<string> {
  const key = password.length >= 16 ? password.slice(0, 16) : password.padEnd(16, '0');
  
  // 解码 base64 字符串到 Uint8Array
  const binaryString = atob(encryptedData);
  const combinedData = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    combinedData[i] = binaryString.charCodeAt(i);
  }
  
  const iv = combinedData.slice(0, 16);
  const encrypted = combinedData.slice(16);
  
  const keyBuffer = new TextEncoder().encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-CBC', length: 128 },
    false,
    ['decrypt']
  );
  
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    encrypted
  );
  
  return new TextDecoder().decode(decryptedData);
}