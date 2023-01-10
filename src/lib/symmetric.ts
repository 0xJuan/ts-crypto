import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto'


export const encrypt = (key: string, cleartext: string, algorithm: string = 'aes256'): string => {
    const _salt = randomBytes(8).toString('hex')
    const _hash = scryptSync(key, _salt, 32)
    const _iv = randomBytes(8).toString('hex')
    const _cipher = createCipheriv(algorithm, _hash, _iv)
    let encrypted = _cipher.update(cleartext, 'utf8', 'hex')
    encrypted += _cipher.final('hex')
    return `${_salt}:${_iv}:${encrypted}`
}

export const decrypt = (key: string, encryptedtext: string, algorithm: string = 'aes256'): string => {
    const [_salt, _iv, _encryptedtext] = encryptedtext.split(':')
    const _hash = scryptSync(key, _salt, 32)
    const _decipher = createDecipheriv(algorithm, _hash, _iv)
    let decrypted = _decipher.update(_encryptedtext, 'hex', 'utf8')
    decrypted += _decipher.final('utf8')
    return decrypted
}
